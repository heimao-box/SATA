# SATA Security Analysis Platform

[English](#english) | [中文](#中文)

## English

### Overview
SATA is a Windows-focused security analysis platform that combines YARA-based static scanning with dynamic behavioral monitoring. It provides a clean SaaS-style UI, risk scoring, execution flow visualization, history reports, PDF export, and bilingual navigation.

### Features
- Static analysis via YARA rules
- Dynamic analysis (Process, FileSystem, Registry, Network) with 30s auto-stop
- Risk scoring (0–30): `Safe ≤10`, `Suspicious 11–20`, `Malicious ≥21`
- Execution flow SVG with item click details
- History reports with verdict visibility and one-click delete
- PDF report export (HTML fallback)
- Bilingual taskbar (Chinese/English)
- Unique filenames on upload to avoid locks; Windows-safe networking (AF_UNIX guard)

### Directory
```
.
├─ app.py               # Flask app entry
├─ templates/           # Jinja2 templates (index, analyze, progress, reports, about)
├─ static/              # styles.css (SaaS white theme)
├─ uploads/             # uploaded samples
├─ analysis/            # dynamic JSON, flow SVG, exported PDFs/HTML
├─ bin/                 # yara64.exe (preferred location)
├─ yara_rules/          # .yar rule files
└─ ProcDetective/       # monitoring modules (process, fs, registry, network)
```

### Getting Started
- Requirements: Python 3.10+, Windows, `yara64.exe`
- Install:
  ```
  python -m pip install -r requirements.txt
  ```
- Run:
  ```
  python app.py
  ```
- Access: `http://127.0.0.1:5000/`

### Usage
- Upload a file on the home page; progress page shows steps and time remaining
- After ~30s, dynamic monitoring stops and the report page shows:
  - File info, static matches, dynamic events summary, risk verdict
  - Execution flow SVG (interactive on the webpage)
  - Export PDF via “Export PDF” button
- History reports:
  - View verdict and score
  - Download dynamic JSON
  - View SVG flow
  - Delete report with one click

### Routes
- `/` Home (upload and analyze)
- `/upload` POST file
- `/analyze/<filename>` Report page
- `/reports` History reports
- `/export/pdf/<filename>` Export PDF
- `/reports/delete/<name>` Delete history report artifacts
- `/set-lang/<code>` Toggle language (`zh` or `en`)

### Risk Scoring
- Static points: severity and category weights (capped 20)
- Dynamic points: operation weights and combined heuristics (capped 10)
- Verdict: `safe`, `suspicious`, `malicious`

### Notes
- PDF generation uses `xhtml2pdf`; if unavailable or rendering fails, HTML is provided
- Execution flow SVG is best viewed on the website; PDF includes file reference
- Run samples in a controlled environment

---

## 中文

### 概述
SATA 是面向 Windows 的安全分析平台，结合 YARA 静态扫描与动态行为监控。平台提供 SaaS 风格白色 UI、风险评分、执行流可视化、历史报告、PDF 导出，以及中英文切换。

### 功能
- 基于 YARA 的静态分析
- 动态分析（进程、文件系统、注册表、网络），约 30 秒后自动停止
- 风险评分（0–30）：`安全 ≤10`、`可疑 11–20`、`恶意 ≥21`
- 执行流 SVG，支持点击查看详细信息
- 历史报告展示判定与评分，一键删除
- PDF 报告导出（失败自动回退为 HTML）
- 任务栏中英文切换
- 上传生成唯一文件名避免锁定；网络监控兼容 Windows（AF_UNIX 保护）

### 目录结构
```
.
├─ app.py               # Flask 应用入口
├─ templates/           # 模板（index、analyze、progress、reports、about）
├─ static/              # styles.css（企业白色风格）
├─ uploads/             # 上传样本
├─ analysis/            # 动态 JSON、执行流 SVG、导出的 PDF/HTML
├─ bin/                 # yara64.exe（优选位置）
├─ yara_rules/          # .yar 规则文件
└─ ProcDetective/       # 监控模块（进程、文件系统、注册表、网络）
```

### 快速开始
- 环境要求：Python 3.10+、Windows、`yara64.exe`
- 安装依赖：
  ```
  python -m pip install -r requirements.txt
  ```
- 启动：
  ```
  python app.py
  ```
- 访问：`http://127.0.0.1:5000/`

### 使用说明
- 在首页上传文件；进入进度页查看步骤与剩余时间
- 约 30 秒后动态监控自动停止，报告页显示：
  - 文件信息、静态规则命中、动态事件概要、风险判定与评分
  - 执行流 SVG（网页交互查看）
  - 点击“导出 PDF”下载报告
- 历史报告：
  - 可直接看到判定与评分
  - 下载动态 JSON
  - 查看执行流 SVG
  - 一键删除报告数据

### 路由
- `/` 首页（上传与分析）
- `/upload` 上传文件
- `/analyze/<filename>` 报告页面
- `/reports` 历史报告
- `/export/pdf/<filename>` 导出 PDF
- `/reports/delete/<name>` 删除历史报告数据
- `/set-lang/<code>` 切换语言（`zh` 或 `en`）

### 评分说明
- 静态分：按严重性与类别加权（封顶 20）
- 动态分：按操作加权与组合规则（封顶 10）
- 判定：`安全`、`可疑`、`恶意`

### 说明
- PDF 使用 `xhtml2pdf`，失败时提供 HTML
- 执行流 SVG 建议在网页查看；PDF 中为文件名提示
- 请在受控环境中分析样本
