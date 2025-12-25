from pathlib import Path
import sys
import os
import json
import hashlib
import subprocess
import threading
import time
from datetime import datetime
from collections import deque
from flask import Flask, request, redirect, url_for, render_template, send_from_directory, jsonify
from werkzeug.utils import secure_filename
from io import BytesIO

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
BIN_DIR = BASE_DIR / "bin"
ANALYSIS_DIR = BASE_DIR / "analysis"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
YARA_RULES_DIR = BASE_DIR / "yara_rules"
YARA_EXE = BIN_DIR / "yara64.exe" if (BIN_DIR / "yara64.exe").exists() else (BASE_DIR / "yara64.exe")

for d in [UPLOAD_DIR, BIN_DIR, ANALYSIS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

sys.path.append(str(BASE_DIR / "ProcDetective"))
from procmon import ProcMon, EventFilter, EventType  # type: ignore
from enhanced_process_monitor import EnhancedProcessMonitor  # type: ignore
from enhanced_filesystem_monitor import EnhancedFileSystemMonitor  # type: ignore
from enhanced_registry_monitor import EnhancedRegistryMonitor  # type: ignore
from enhanced_network_monitor import EnhancedNetworkMonitor  # type: ignore
from process_monitor import ProcessMonitor  # type: ignore

app = Flask(__name__, template_folder=str(TEMPLATES_DIR), static_folder=str(STATIC_DIR))
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)

monitor_lock = threading.Lock()
procmon_instance = None
events_buffer = deque(maxlen=5000)
monitor_running = False
current_dynamic_target = {"process_name": None, "pid": None, "popen": None}
analysis_jobs: dict[str, dict] = {}


def file_hashes(fp: Path) -> dict:
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with fp.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {
        "md5": h_md5.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "sha256": h_sha256.hexdigest(),
    }


def guess_mime(ext: str) -> str:
    mapping = {
        "exe": "application/x-msdownload",
        "dll": "application/x-msdownload",
        "com": "application/x-msdownload",
        "scr": "application/x-msdownload",
        "bat": "application/x-bat",
        "cmd": "application/x-bat",
        "ps1": "text/plain",
        "vbs": "text/vbscript",
        "js": "application/javascript",
        "jar": "application/java-archive",
        "apk": "application/vnd.android.package-archive",
        "zip": "application/zip",
        "rar": "application/x-rar-compressed",
        "txt": "text/plain",
        "pdf": "application/pdf",
        "doc": "application/msword",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls": "application/vnd.ms-excel",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
    return mapping.get(ext.lower(), "application/octet-stream")


def file_type(ext: str) -> str:
    mapping = {
        "exe": "Windows可执行文件",
        "dll": "Windows动态链接库",
        "com": "DOS可执行文件",
        "scr": "屏幕保护程序",
        "bat": "批处理文件",
        "cmd": "命令脚本",
        "ps1": "PowerShell脚本",
        "vbs": "VBScript脚本",
        "js": "JavaScript文件",
        "jar": "Java归档文件",
        "apk": "Android应用包",
        "zip": "ZIP压缩文件",
        "rar": "RAR压缩文件",
    }
    return mapping.get(ext.lower(), "未知类型")


def is_pe(fp: Path) -> bool:
    try:
        with fp.open("rb") as f:
            header = f.read(2)
            return header == b"MZ"
    except Exception:
        return False


def parse_rule_meta(rule_file: Path, rule_name: str) -> dict:
    try:
        content = rule_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {}
    key = f"rule {rule_name}"
    idx = content.find(key)
    if idx == -1:
        return {}
    meta_idx = content.find("meta:", idx)
    if meta_idx == -1:
        return {}
    end_idx = content.find("strings:", meta_idx)
    if end_idx == -1:
        end_idx = content.find("condition:", meta_idx)
    if end_idx == -1:
        end_idx = meta_idx + 300
    meta_block = content[meta_idx:end_idx]
    result = {}
    for line in meta_block.splitlines():
        line = line.strip()
        if "=" in line:
            parts = line.split("=", 1)
            k = parts[0].strip()
            v = parts[1].strip().strip('"')
            result[k] = v
    return result


def run_yara_scan(target_file: Path) -> dict:
    matches = []
    if not YARA_EXE.exists():
        return {"error": "yara64.exe未找到", "matches": []}
    for rule_file in sorted(YARA_RULES_DIR.glob("*.yar")):
        try:
            cmd = [str(YARA_EXE), str(rule_file), str(target_file)]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if p.returncode == 0 and p.stdout:
                for line in p.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    rule = parts[0]
                    meta = parse_rule_meta(rule_file, rule)
                    matches.append(
                        {
                            "rule": rule,
                            "rule_file": rule_file.name,
                            "severity": meta.get("severity", "medium"),
                            "category": meta.get("category", "general"),
                            "description": meta.get("description", ""),
                        }
                    )
        except subprocess.TimeoutExpired:
            matches.append(
                {
                    "rule": f"Timeout_{rule_file.name}",
                    "rule_file": rule_file.name,
                    "severity": "low",
                    "category": "tooling",
                    "description": "规则执行超时",
                }
            )
        except Exception as e:
            matches.append(
                {
                    "rule": f"Error_{rule_file.name}",
                    "rule_file": rule_file.name,
                    "severity": "low",
                    "category": "tooling",
                    "description": str(e),
                }
            )
    categories = {}
    for m in matches:
        c = m.get("category", "general")
        categories[c] = categories.get(c, 0) + 1
    return {"matches": matches, "categories": categories}


def build_file_info(fp: Path) -> dict:
    ext = fp.suffix[1:].lower()
    info = {
        "size": fp.stat().st_size if fp.exists() else 0,
        "md5": "",
        "sha1": "",
        "sha256": "",
        "mime_type": guess_mime(ext),
        "file_type": file_type(ext),
        "creation_time": datetime.fromtimestamp(fp.stat().st_ctime).strftime("%Y-%m-%d %H:%M:%S") if fp.exists() else "",
        "modification_time": datetime.fromtimestamp(fp.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S") if fp.exists() else "",
    }
    if fp.exists():
        info.update(file_hashes(fp))
        info["is_pe"] = is_pe(fp)
    return info


def monitor_callback(event):
    try:
        data = {
            "timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "event_type": event.event_type.value,
            "operation": event.operation.value,
            "process_name": event.process_name,
            "process_id": event.process_id,
            "path": event.path,
            "result": event.result,
            "details": event.details,
        }
        events_buffer.append(data)
    except Exception:
        pass


def get_filtered_events(name: str | None, pid: int | None, limit: int = 200) -> list[dict]:
    def _aliases(n: str) -> set[str]:
        try:
            n = n.lower()
            if not n:
                return set()
            base = Path(n).stem
            al = {n, base, f"{base}.exe"}
            # 处理形如 name_123456.exe 的时间戳后缀
            if "_" in base:
                parts = base.split("_")
                if parts[-1].isdigit():
                    clean = "_".join(parts[:-1])
                    al.update({clean, f"{clean}.exe"})
            return {a for a in al if a}
        except Exception:
            return {n}
    filtered = []
    for e in list(events_buffer)[-1000:]:
        try:
            dn = (name or "")
            en = str(e.get("process_name", "")).lower()
            ep = e.get("process_id")
            det = e.get("details") or {}
            pi = det.get("process_info") or {}
            pin = str(pi.get("name", "")).lower()
            pip = pi.get("pid")
            path = str(e.get("path", "")).lower()
            alias = _aliases(dn)
            if dn and en and (en in alias or en.strip(".exe") in alias):
                filtered.append(e)
                continue
            if pid and ep and ep == pid:
                filtered.append(e)
                continue
            if dn and pin and (pin in alias or pin.strip(".exe") in alias):
                filtered.append(e)
                continue
            if pid and pip and pip == pid:
                filtered.append(e)
                continue
            if dn and path and any(a in path for a in alias):
                filtered.append(e)
        except Exception:
            continue
    return filtered[-limit:]


def summarize_events(events: list[dict]) -> dict:
    by_type = {}
    by_op = {}
    for e in events:
        t = e.get("event_type")
        o = e.get("operation")
        if t:
            by_type[t] = by_type.get(t, 0) + 1
        if o:
            by_op[o] = by_op.get(o, 0) + 1
    return {"by_type": by_type, "by_operation": by_op, "count": len(events)}


def evaluate_risk(scan_result: dict, dyn_events: list[dict], file_info: dict) -> dict:
    static_points = 0
    sev_w = {"high": 3, "medium": 2, "low": 1}
    cat_bonus = {"injection": 2, "persistence": 2, "obfuscation": 2, "evasion": 1, "keylogger": 3, "packer": 1, "anti_analysis": 1}
    for m in scan_result.get("matches", []):
        static_points += sev_w.get(str(m.get("severity", "")).lower(), 1)
        c = str(m.get("category", "")).lower()
        static_points += cat_bonus.get(c, 0)
    static_points = min(static_points, 20)
    dyn_points = 0
    ops_w = {
        "RegWrite": 2, "RegSetValue": 2, "RegCreateKey": 2, "RegDeleteKey": 2, "RegDelete": 2,
        "FileDelete": 2, "FILE_DELETE": 2, "FileWrite": 1, "FILE_WRITE": 1, "FileCreate": 1, "FILE_CREATE": 1,
        "NetConnect": 1, "NETWORK_CONNECT": 1, "NetSend": 1, "NetReceive": 1, "NETWORK_LISTEN": 2, "NetworkListen": 2,
        "ProcessCreate": 1, "ThreadCreate": 1, "ModuleLoad": 1
    }
    ops_set = set()
    for e in dyn_events:
        op = e.get("operation", "")
        ops_set.add(op)
        dyn_points += ops_w.get(str(op), 0)
    if ({"RegWrite", "RegSetValue"} & ops_set) and ({"NetConnect", "NETWORK_CONNECT"} & ops_set):
        dyn_points += 2
    dyn_points = min(dyn_points, 10)
    total = min(30, static_points + dyn_points)
    code = "safe"
    if total > 20:
        code = "malicious"
    elif total >= 10:
        code = "suspicious"
    return {
        "score": total,
        "verdict_code": code,
        "static_points": static_points,
        "dynamic_points": dyn_points
    }


def start_monitors(process_name: str | None = None):
    global procmon_instance, monitor_running
    with monitor_lock:
        if monitor_running:
            return
        procmon_instance = ProcMon()
        ef = EventFilter()
        procmon_instance.set_filter(ef)
        target_set = None
        if process_name:
            try:
                base = Path(process_name).stem
                target_set = {
                    process_name,
                    process_name.lower(),
                    base,
                    base.lower(),
                    f"{base}.exe",
                    f"{base.lower()}.exe",
                }
                if "_" in base:
                    parts = base.split("_")
                    if parts[-1].isdigit():
                        clean = "_".join(parts[:-1])
                        target_set.update({clean, clean.lower(), f"{clean}.exe", f"{clean.lower()}.exe"})
            except Exception:
                target_set = {process_name}
        process_monitor = EnhancedProcessMonitor(monitor_callback, target_set, True, True, False, True)
        watch_paths = [str(UPLOAD_DIR), str(BASE_DIR)]
        try:
            home_dir = str(Path.home())
            if os.path.exists(home_dir):
                watch_paths.append(home_dir)
        except Exception:
            pass
        try:
            tmp_dir = os.environ.get("TEMP") or os.environ.get("TMP")
            if tmp_dir and os.path.exists(tmp_dir):
                watch_paths.append(tmp_dir)
        except Exception:
            pass
        fs_monitor = EnhancedFileSystemMonitor(monitor_callback, watch_paths, True, True, False, target_set)
        registry_monitor = EnhancedRegistryMonitor(monitor_callback)
        network_monitor = EnhancedNetworkMonitor(monitor_callback, True, True, True, None, target_set)
        procmon_instance.add_monitor(process_monitor)
        basic_process_monitor = ProcessMonitor(monitor_callback, target_set)
        procmon_instance.add_monitor(basic_process_monitor)
        procmon_instance.add_monitor(fs_monitor)
        procmon_instance.add_monitor(registry_monitor)
        procmon_instance.add_monitor(network_monitor)
        monitor_running = True
        threading.Thread(target=procmon_instance.start_monitoring, daemon=True).start()


def stop_monitors():
    global procmon_instance, monitor_running
    with monitor_lock:
        if procmon_instance:
            procmon_instance.stop_monitoring()
        monitor_running = False


def stop_dynamic():
    try:
        stop_monitors()
        p = current_dynamic_target.get("popen")
        if p:
            try:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except Exception:
                    p.kill()
            except Exception:
                pass
    finally:
        current_dynamic_target["process_name"] = None
        current_dynamic_target["pid"] = None
        current_dynamic_target["popen"] = None


def write_dynamic_json(name: str, events: list[dict], target: dict) -> str:
    data = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "events": events,
    }
    fn = f"{name}_dynamic.json"
    out = ANALYSIS_DIR / fn
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return fn


def finalize_job(name: str):
    job = analysis_jobs.get(name)
    if not job:
        return
    started_at = job.get("started_at", time.time())
    duration = job.get("duration", 30)
    remaining = duration - (time.time() - started_at)
    if remaining > 0:
        time.sleep(remaining)
    events = get_filtered_events(name, job.get("pid"), 1000)
    json_name = write_dynamic_json(name, events, {"process_name": name, "pid": job.get("pid")})
    flow_name = None
    if events:
        try:
            flow_name = generate_execution_flow_svg(events, name)
        except Exception:
            flow_name = None
    try:
        stop_dynamic()
    except Exception:
        pass
    job.update({
        "status": "complete",
        "completed_at": time.time(),
        "json_name": json_name,
        "flow_name": flow_name,
    })


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        return redirect(url_for("index"))
    filename = secure_filename(f.filename)
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    unique_name = f"{stem}_{int(time.time())}{suffix}" if suffix else f"{stem}_{int(time.time())}"
    dest = UPLOAD_DIR / unique_name
    try:
        f.save(str(dest))
    except PermissionError:
        alt_name = f"{stem}_{int(time.time())}_{os.getpid()}{suffix}"
        dest = UPLOAD_DIR / alt_name
        f.save(str(dest))
    ext = dest.suffix.lower()
    if ext == ".exe":
        try:
            current_dynamic_target["process_name"] = dest.name
            start_monitors(dest.name)
            p = subprocess.Popen([str(dest)], cwd=str(UPLOAD_DIR))
            current_dynamic_target["pid"] = p.pid
            current_dynamic_target["popen"] = p
            analysis_jobs[dest.name] = {
                "status": "running",
                "started_at": time.time(),
                "duration": 30,
                "pid": p.pid,
            }
            threading.Thread(target=finalize_job, args=(dest.name,), daemon=True).start()
        except Exception:
            pass
    return redirect(url_for("progress", filename=dest.name))


@app.route("/analyze/<filename>", methods=["GET"])
def analyze(filename):
    fp = UPLOAD_DIR / filename
    if not fp.exists():
        return redirect(url_for("index"))
    info = build_file_info(fp)
    scan = run_yara_scan(fp)
    job = analysis_jobs.get(filename, {})
    dyn_json = ANALYSIS_DIR / f"{filename}_dynamic.json"
    if dyn_json.exists():
        try:
            data = json.loads(dyn_json.read_text(encoding="utf-8"))
            dyn_events = data.get("events", [])
        except Exception:
            dyn_events = get_filtered_events(filename, job.get("pid"), 500)
    else:
        dyn_events = get_filtered_events(filename, job.get("pid"), 500)
    dyn_summary = summarize_events(dyn_events)
    flow_image_name = None
    flow_fp = ANALYSIS_DIR / f"{filename}_flow.svg"
    if flow_fp.exists():
        flow_image_name = flow_fp.name
    risk = evaluate_risk(scan, dyn_events, info)
    return render_template(
        "analyze.html",
        filename=filename,
        file_info=info,
        scan_result=scan,
        dynamic_events=dyn_events,
        dynamic_summary=dyn_summary,
        dynamic_running=monitor_running,
        dynamic_target=current_dynamic_target,
        flow_image_name=flow_image_name,
        risk=risk,
    )


@app.route("/dynamic/start", methods=["POST"])
def dynamic_start():
    name = request.form.get("process_name") or None
    current_dynamic_target["process_name"] = name
    current_dynamic_target["pid"] = None
    current_dynamic_target["popen"] = None
    start_monitors(name)
    return redirect(url_for("dynamic"))


@app.route("/dynamic/stop", methods=["POST"])
def dynamic_stop():
    stop_monitors()
    return redirect(url_for("dynamic"))


@app.route("/dynamic", methods=["GET"])
def dynamic():
    return render_template("dynamic.html", running=monitor_running)


@app.route("/dynamic/events", methods=["GET"])
def dynamic_events():
    target_name = current_dynamic_target.get("process_name")
    target_pid = current_dynamic_target.get("pid")
    filtered = []
    for e in list(events_buffer)[-1000:]:
        try:
            dn = str(target_name or "")
            en = str(e.get("process_name", "")).lower()
            ep = e.get("process_id")
            det = e.get("details") or {}
            pi = det.get("process_info") or {}
            pin = str(pi.get("name", "")).lower()
            pip = pi.get("pid")
            path = str(e.get("path", "")).lower()
            alias = set()
            if dn:
                alias.add(dn.lower())
                base = Path(dn).stem.lower()
                alias.update({base, f"{base}.exe"})
                if "_" in base:
                    parts = base.split("_")
                    if parts[-1].isdigit():
                        clean = "_".join(parts[:-1])
                        alias.update({clean, f"{clean}.exe"})
            if dn and en and (en in alias or en.strip(".exe") in alias):
                filtered.append(e)
                continue
            if target_pid and ep and ep == target_pid:
                filtered.append(e)
                continue
            if dn and pin and (pin in alias or pin.strip(".exe") in alias):
                filtered.append(e)
                continue
            if target_pid and pip and pip == target_pid:
                filtered.append(e)
                continue
            if dn and path and any(a in path for a in alias):
                filtered.append(e)
        except Exception:
            continue
    return jsonify({"running": monitor_running, "target": current_dynamic_target, "events": filtered[-200:]})


@app.route("/dynamic/export", methods=["GET"])
def dynamic_export():
    target_name = current_dynamic_target.get("process_name")
    target_pid = current_dynamic_target.get("pid")
    alias = set()
    if target_name:
        try:
            tn = str(target_name)
            alias.add(tn.lower())
            base = Path(tn).stem.lower()
            alias.update({base, f"{base}.exe"})
            if "_" in base:
                parts = base.split("_")
                if parts[-1].isdigit():
                    clean = "_".join(parts[:-1])
                    alias.update({clean, f"{clean}.exe"})
        except Exception:
            alias.add(str(target_name).lower())
    data = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": current_dynamic_target,
        "events": [
            e for e in list(events_buffer)
            if (
                (target_name and (
                    str(e.get("process_name","")).lower() in alias
                    or str((e.get("details") or {}).get("process_info", {}).get("name","")).lower() in alias
                    or any(a in str(e.get("path","")).lower() for a in alias)
                ))
                or (target_pid and e.get("process_id") == target_pid)
                or (target_pid and (e.get("details") or {}).get("process_info", {}).get("pid") == target_pid)
            )
        ],
    }
    try:
        fn = f"{target_name or 'session'}_dynamic.json"
        out = ANALYSIS_DIR / fn
        out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return send_from_directory(str(ANALYSIS_DIR), fn, as_attachment=True)
    except Exception:
        return jsonify(data)


def generate_execution_flow_svg(events: list[dict], target_name: str | None) -> str:
    width = 1000
    margin = 20
    step = 50
    count = len(events)
    height = max(200, margin * 2 + step * (count + 1))
    colors = {
        "Process": "#3b82f6",
        "FileSystem": "#22c55e",
        "Registry": "#f59e0b",
        "Network": "#ef4444",
        "Default": "#64748b",
    }
    def color_for(t: str) -> str:
        return colors.get(t, colors["Default"])
    y = margin + 40
    items = []
    items.append(f'<text x="{width/2}" y="{margin+10}" fill="#e5e7eb" font-size="16" text-anchor="middle">执行流 {target_name or ""}</text>')
    prev_y = None
    for idx, e in enumerate(events):
        x = 100
        w = width - 200
        h = 30
        fill = color_for(e.get("event_type","Default"))
        ts = e.get("timestamp","")
        label = f'{e.get("event_type","")} • {e.get("operation","")}'
        path = e.get("path","")
        items.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" ry="8" fill="{fill}" opacity="0.25" stroke="{fill}" />')
        items.append(f'<text x="{x+10}" y="{y+20}" fill="#e5e7eb" font-size="12">{label}</text>')
        items.append(f'<text x="{x+w-10}" y="{y+20}" fill="#9ca3af" font-size="12" text-anchor="end">{ts}</text>')
        items.append(f'<text x="{x+10}" y="{y+38}" fill="#9ca3af" font-size="11">{path}</text>')
        if prev_y is not None:
            ax = width/2
            items.append(f'<line x1="{ax}" y1="{prev_y+h}" x2="{ax}" y2="{y}" stroke="#475569" stroke-width="2" />')
            items.append(f'<polygon points="{ax-5},{y} {ax+5},{y} {ax},{y-8}" fill="#475569" />')
        prev_y = y
        y += step
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" style="background:#0b1220;">' + "".join(items) + '</svg>'
    name = f'{(target_name or "session").replace(" ","_")}_flow.svg'
    out = ANALYSIS_DIR / name
    out.write_text(svg, encoding="utf-8")
    return name


@app.route("/uploads/<path:path>", methods=["GET"])
def downloads(path):
    return send_from_directory(str(UPLOAD_DIR), path, as_attachment=True)

@app.route("/analysis/<path:path>", methods=["GET"])
def analysis_file(path):
    return send_from_directory(str(ANALYSIS_DIR), path, as_attachment=False)

@app.route("/reports", methods=["GET"])
def reports():
    items = []
    for fp in sorted(ANALYSIS_DIR.glob("*_dynamic.json")):
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
            target = data.get("target", {})
            name = target.get("process_name") or fp.stem.replace("_dynamic", "")
            gen = data.get("generated_at") or ""
            evts = data.get("events", [])
            flow_svg = ANALYSIS_DIR / f"{name}_flow.svg"
            exists = (UPLOAD_DIR / name).exists()
            risk = None
            verdict_class = None
            if exists:
                info = build_file_info(UPLOAD_DIR / name)
                scan = run_yara_scan(UPLOAD_DIR / name)
                risk = evaluate_risk(scan, evts, info)
                verdict_class = f"verdict-{risk['verdict_code']}"
            items.append({
                "name": name,
                "generated_at": gen,
                "events_count": len(evts),
                "json_url": url_for("analysis_file", path=fp.name),
                "flow_url": url_for("analysis_file", path=flow_svg.name) if flow_svg.exists() else None,
                "analyze_url": url_for("analyze", filename=name),
                "exists_in_uploads": exists,
                "risk": risk,
                "verdict_class": verdict_class
            })
        except Exception:
            continue
    return render_template("reports.html", items=items)

@app.route("/progress/<filename>", methods=["GET"])
def progress(filename):
    job = analysis_jobs.get(filename)
    return render_template("progress.html", filename=filename, job=job)

@app.route("/progress/status/<filename>", methods=["GET"])
def progress_status(filename):
    job = analysis_jobs.get(filename, {})
    status = job.get("status", "unknown")
    duration = job.get("duration", 30)
    started_at = job.get("started_at", time.time())
    elapsed = time.time() - started_at
    percent = int(max(0, min(100, (elapsed / duration) * 100)))
    if status == "complete":
        percent = 100
    return jsonify({"status": status, "percent": percent, "elapsed": int(elapsed), "duration": duration})

@app.route("/export/pdf/<filename>", methods=["GET"])
def export_pdf(filename: str):
    fp = UPLOAD_DIR / filename
    if not fp.exists():
        return redirect(url_for("index"))
    info = build_file_info(fp)
    scan = run_yara_scan(fp)
    # 动态数据与概要
    dyn_json = ANALYSIS_DIR / f"{filename}_dynamic.json"
    if dyn_json.exists():
        try:
            data = json.loads(dyn_json.read_text(encoding="utf-8"))
            dyn_events = data.get("events", [])
        except Exception:
            dyn_events = []
    else:
        dyn_events = []
    dyn_summary = summarize_events(dyn_events)
    risk = evaluate_risk(scan, dyn_events, info)
    flow_svg_path = ANALYSIS_DIR / f"{filename}_flow.svg"
    # 生成 HTML
    lang_code = get_lang()
    html = f"""
<!doctype html>
<html lang="{ 'en' if lang_code=='en' else 'zh-CN' }">
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: DejaVu Sans, Arial, sans-serif; color: #111827; }}
    h1, h2, h3 {{ margin: 0 0 8px 0; }}
    .section {{ margin-bottom: 16px; }}
    .table {{ width: 100%; border-collapse: collapse; }}
    .table th, .table td {{ border: 1px solid #e5e7eb; padding: 8px; font-size: 12px; }}
    .badge {{ display: inline-block; padding: 4px 8px; border-radius: 6px; font-size: 12px; }}
    .safe {{ background: #dcfce7; color: #166534; }}
    .suspicious {{ background: #fef3c7; color: #92400e; }}
    .malicious {{ background: #fee2e2; color: #7f1d1d; }}
    .tag {{ display:inline-block; border:1px solid #e5e7eb; padding:4px 6px; border-radius:999px; margin:2px; font-size:11px; }}
    .small {{ color:#6b7280; font-size:11px }}
  </style>
</head>
<body>
  <h1>{t('export.title')}</h1>
  <div class="section small">{t('export.generated_at')}：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
  <div class="section">
    <h2>{t('export.overview')}</h2>
    <div>{t('file.label')}：<strong>{filename}</strong></div>
    <div>{t('common.score')}：<strong>{risk["score"]}</strong> / 30</div>
    <div>{t('common.verdict')}：
      <span class="badge {risk['verdict_code']}">{t('verdict.' + risk["verdict_code"])}</span>
    </div>
  </div>
  <div class="section">
    <h2>{t('analyze.file_info')}</h2>
    <table class="table">
      <tr><th>{t('file.size')}</th><td>{info["size"]}</td></tr>
      <tr><th>{t('file.type')}</th><td>{info["file_type"]}</td></tr>
      <tr><th>{t('file.mime')}</th><td>{info["mime_type"]}</td></tr>
      <tr><th>MD5</th><td>{info["md5"]}</td></tr>
      <tr><th>SHA1</th><td>{info["sha1"]}</td></tr>
      <tr><th>SHA256</th><td>{info["sha256"]}</td></tr>
      <tr><th>{t('file.created_at')}</th><td>{info["creation_time"]}</td></tr>
      <tr><th>{t('file.modified_at')}</th><td>{info["modification_time"]}</td></tr>
      <tr><th>PE</th><td>{t('common.yes') if info["is_pe"] else t('common.no')}</td></tr>
    </table>
  </div>
  <div class="section">
    <h2>{t('analyze.static_detection') if t('analyze.static_detection')!='analyze.static_detection' else 'Static Detection'}</h2>
    <div class="small">{t('export.matches_count')}：{len(scan.get("matches", []))}；{t('export.contribution_points')}：{risk["static_points"]}</div>
    <div>
      {''.join([f'<span class="tag">{k} {v}</span>' for k, v in scan.get("categories", {}).items()])}
    </div>
    <table class="table">
      <tr><th>{t('analyze.rule')}</th><th>{t('analyze.severity') if t('analyze.severity')!='analyze.severity' else 'Severity'}</th><th>{t('analyze.category')}</th><th>{t('analyze.description') if t('analyze.description')!='analyze.description' else 'Description'}</th></tr>
      {''.join([f"<tr><td>{m.get('rule','')}</td><td>{m.get('severity','')}</td><td>{m.get('category','')}</td><td>{m.get('description','')}</td></tr>" for m in scan.get("matches", [])])}
    </table>
  </div>
  <div class="section">
    <h2>{t('export.dynamic_summary')}</h2>
    <div class="small">{t('reports.events_count')}：{dyn_summary["count"]}；{t('export.contribution_points')}：{risk["dynamic_points"]}</div>
    <div>
      {''.join([f'<span class="tag">{k} {v}</span>' for k, v in dyn_summary.get("by_type", {}).items()])}
      {''.join([f'<span class="tag">{k} {v}</span>' for k, v in dyn_summary.get("by_operation", {}).items()])}
    </div>
  </div>
  <div class="section">
    <h2>{t('dynamic.flow')}</h2>
    <div class="small">{t('export.flow_note')}</div>
    <div>{t('export.flow_image_file')}：{flow_svg_path.name if flow_svg_path.exists() else ( 'Not generated' if lang_code=='en' else '未生成')}</div>
  </div>
</body>
</html>
    """
    try:
        from xhtml2pdf import pisa  # type: ignore
    except Exception:
        # 依赖未安装时，回退为下载 HTML
        fn_html = ANALYSIS_DIR / f"{filename}_report.html"
        fn_html.write_text(html, encoding="utf-8")
        return send_from_directory(str(ANALYSIS_DIR), fn_html.name, as_attachment=True)
    # 生成 PDF
    pdf_io = BytesIO()
    result = pisa.CreatePDF(html, dest=pdf_io)
    if result.err:
        # 失败时回退为 HTML
        fn_html = ANALYSIS_DIR / f"{filename}_report.html"
        fn_html.write_text(html, encoding="utf-8")
        return send_from_directory(str(ANALYSIS_DIR), fn_html.name, as_attachment=True)
    pdf_io.seek(0)
    out_path = ANALYSIS_DIR / f"{filename}_report.pdf"
    with out_path.open("wb") as f:
        f.write(pdf_io.read())
    return send_from_directory(str(ANALYSIS_DIR), out_path.name, as_attachment=True)

@app.route("/reports/delete/<name>", methods=["POST"])
def reports_delete(name: str):
    base = secure_filename(name)
    if not base:
        return jsonify({"success": False, "error": "invalid name"}), 400
    removed = []
    errors = []
    for suf in ["_dynamic.json", "_flow.svg", "_report.pdf", "_report.html"]:
        fp = ANALYSIS_DIR / f"{base}{suf}"
        if fp.exists():
            try:
                fp.unlink()
                removed.append(fp.name)
            except Exception as e:
                errors.append(str(e))
    return jsonify({"success": True, "removed": removed, "errors": errors})

def get_lang() -> str:
    v = request.cookies.get("lang", "zh")
    return "en" if v.lower().startswith("en") else "zh"

def t(key: str) -> str:
    zh = {
        "title.platform": "SATA 安全分析平台",
        "nav.files": "文件分析",
        "nav.reports": "历史报告",
        "lang.zh": "中文",
        "lang.en": "English",
        "index.upload_analyze": "上传并分析文件",
        "index.upload_analyze_button": "上传并分析",
        "common.score": "评分",
        "common.verdict": "判定",
        "common.yes": "是",
        "common.no": "否",
        "common.unknown": "未知",
        "file.label": "文件",
        "file.size": "大小",
        "file.bytes": "字节",
        "file.type": "类型",
        "file.mime": "MIME",
        "file.created_at": "创建时间",
        "file.modified_at": "修改时间",
        "file.download": "下载文件",
        "analyze.result_title": "分析结果",
        "analyze.risk_score": "风险评分",
        "analyze.file_info": "文件信息",
        "analyze.static_points": "静态贡献",
        "analyze.dynamic_points": "动态贡献",
        "analyze.export_pdf": "导出PDF",
        "analyze.detections": "检测结果",
        "analyze.no_detection": "未检测到可疑特征",
        "analyze.suspicious_pattern_detected": "检测到可疑模式",
        "analyze.rule": "规则",
        "analyze.category": "类别",
        "dynamic.analysis": "动态分析",
        "dynamic.monitor": "动态监控",
        "dynamic.target": "目标",
        "dynamic.export_json": "导出动态数据(JSON)",
        "dynamic.no_events": "尚无与该样本相关的动态事件",
        "dynamic.flow": "执行流",
        "dynamic.events": "事件",
        "dynamic.target_process_placeholder": "目标进程名(可选)",
        "dynamic.start": "启动监控",
        "dynamic.stop": "停止监控",
        "status.running": "运行中",
        "status.stopped": "已停止",
        "progress.title": "分析任务",
        "progress.step_static": "初始化静态分析",
        "progress.step_dynamic_start": "启动动态监控",
        "progress.step_collect": "收集行为数据",
        "progress.step_report": "生成报告与执行流",
        "reports.title": "历史报告",
        "reports.empty": "暂无历史报告",
        "reports.events_count": "事件数",
        "reports.upload_file": "上传文件",
        "reports.file_exists": "存在",
        "reports.file_missing": "已缺失",
        "reports.unable_evaluate": "无法评估（缺少文件）",
        "reports.view_report": "查看报告",
        "reports.download_json": "下载动态JSON",
        "reports.view_flow": "查看执行流图",
        "reports.delete": "删除报告",
        "reports.confirm_delete": "确认删除该历史报告？",
        "reports.delete_failed": "删除失败: ",
        "verdict.safe": "安全",
        "verdict.suspicious": "可疑",
        "verdict.malicious": "恶意",
        "export.title": "SATA 安全分析报告",
        "export.generated_at": "生成时间",
        "export.overview": "总体评估",
        "export.matches_count": "命中规则",
        "export.contribution_points": "贡献分",
        "export.dynamic_summary": "动态分析概要",
        "export.flow_note": "由于 PDF 引擎限制，SVG 执行流图建议在网页查看。",
        "export.flow_image_file": "图像文件",
    }
    en = {
        "title.platform": "SATA Security Analysis Platform",
        "nav.files": "File Analysis",
        "nav.reports": "History Reports",
        "lang.zh": "Chinese",
        "lang.en": "English",
        "index.upload_analyze": "Upload and Analyze File",
        "index.upload_analyze_button": "Upload & Analyze",
        "common.score": "Score",
        "common.verdict": "Verdict",
        "common.yes": "Yes",
        "common.no": "No",
        "common.unknown": "Unknown",
        "file.label": "File",
        "file.size": "Size",
        "file.bytes": "bytes",
        "file.type": "Type",
        "file.mime": "MIME",
        "file.created_at": "Created At",
        "file.modified_at": "Modified At",
        "file.download": "Download File",
        "analyze.result_title": "Analysis Results",
        "analyze.risk_score": "Risk Score",
        "analyze.file_info": "File Info",
        "analyze.static_points": "Static Points",
        "analyze.dynamic_points": "Dynamic Points",
        "analyze.export_pdf": "Export PDF",
        "analyze.detections": "Detections",
        "analyze.no_detection": "No suspicious patterns detected",
        "analyze.suspicious_pattern_detected": "Suspicious pattern detected",
        "analyze.rule": "Rule",
        "analyze.category": "Category",
        "dynamic.analysis": "Dynamic Analysis",
        "dynamic.monitor": "Dynamic Monitor",
        "dynamic.target": "Target",
        "dynamic.export_json": "Export dynamic data (JSON)",
        "dynamic.no_events": "No dynamic events related to this sample",
        "dynamic.flow": "Execution Flow",
        "dynamic.events": "Events",
        "dynamic.target_process_placeholder": "Target process (optional)",
        "dynamic.start": "Start Monitoring",
        "dynamic.stop": "Stop Monitoring",
        "status.running": "Running",
        "status.stopped": "Stopped",
        "progress.title": "Analysis Task",
        "progress.step_static": "Initialize Static Analysis",
        "progress.step_dynamic_start": "Start Dynamic Monitoring",
        "progress.step_collect": "Collect Behavioral Data",
        "progress.step_report": "Generate Report & Execution Flow",
        "reports.title": "History Reports",
        "reports.empty": "No history reports",
        "reports.events_count": "Events",
        "reports.upload_file": "Uploaded file",
        "reports.file_exists": "exists",
        "reports.file_missing": "missing",
        "reports.unable_evaluate": "Unable to evaluate (missing file)",
        "reports.view_report": "View Report",
        "reports.download_json": "Download Dynamic JSON",
        "reports.view_flow": "View Execution Flow",
        "reports.delete": "Delete Report",
        "reports.confirm_delete": "Confirm to delete this history report?",
        "reports.delete_failed": "Delete failed: ",
        "verdict.safe": "Safe",
        "verdict.suspicious": "Suspicious",
        "verdict.malicious": "Malicious",
        "export.title": "SATA Security Analysis Report",
        "export.generated_at": "Generated At",
        "export.overview": "Overview",
        "export.matches_count": "Matches",
        "export.contribution_points": "Contribution Points",
        "export.dynamic_summary": "Dynamic Summary",
        "export.flow_note": "Due to PDF engine limits, view SVG flow on the webpage.",
        "export.flow_image_file": "Image File",
    }
    lang = get_lang()
    table = en if lang == "en" else zh
    return table.get(key, key)

@app.context_processor
def inject_i18n():
    return {"t": t, "lang": get_lang()}

@app.route("/set-lang/<code>", methods=["GET"])
def set_lang(code: str):
    c = "en" if code.lower().startswith("en") else "zh"
    ref = request.referrer or url_for("index")
    resp = redirect(ref)
    resp.set_cookie("lang", c, max_age=60 * 60 * 24 * 365)
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
