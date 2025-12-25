# SATA Security Analysis Platform

<img width="2560" height="1305" alt="image" src="https://github.com/user-attachments/assets/b0e442db-3aa1-4796-ad0c-a4e1303ee0a7" />


### Overview
SATA is a Windows-focused security analysis platform that combines YARA-based static scanning with dynamic behavioral monitoring. It provides a clean SaaS-style UI, risk scoring, execution flow visualization, history reports, PDF export, and bilingual navigation.

Note that it is best to run this platform in a virtual environment, as the platform will execute user uploaded programs for dynamic analysis

### Features
- Static analysis via YARA rules
- Dynamic analysis (Process, FileSystem, Registry, Network) with 30s auto-stop
- Risk scoring (0–30): `Safe ≤10`, `Suspicious 11–20`, `Malicious ≥21`
- Execution flow SVG with item click details
- History reports with verdict visibility and one-click delete
- PDF report export (HTML fallback)
- Bilingual taskbar (Chinese/English)
- Unique filenames on upload to avoid locks; Windows-safe networking (AF_UNIX guard)
<img width="2560" height="1305" alt="image" src="https://github.com/user-attachments/assets/c4f88f7f-c2ee-4ef9-a024-0dbe87cd5dcd" />
<img width="1285" height="1026" alt="image" src="https://github.com/user-attachments/assets/f1161007-a7a0-4768-8d93-397b8357cf52" />

Dynamic analysis can show the network connection of the program, imported files, read files, registry operations, etc. The tool links used are: https://github.com/heimao-box/ProcDetective

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
- You can customize Yara rules
<img width="799" height="326" alt="image" src="https://github.com/user-attachments/assets/768b0945-7202-43b7-99b4-67fd575ac0bd" />


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
