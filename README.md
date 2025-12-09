# CodeX‑V2 – Security & Quality Analyzer

Python-based static analysis toolkit with a REST API and React dashboard. Scans code for dangerous patterns, secrets, crypto/auth issues, framework pitfalls, and dependency CVEs; exports JSON/PDF reports.

## Prerequisites
- Python 3.10+ (3.8+ works; tested on Windows)  
- Node.js 18+ and npm (for the GUI in `gui/`)  
- Optional for richer results: `reportlab` + `matplotlib` (PDF reports), `psutil` (resource stats), `NVD_API_KEY`, `GITHUB_TOKEN`

## Project Structure (top-level)
- `comprehensive_analyzer.py` – one-shot CLI runner (8-stage security/quality scan)
- `analyzer_api.py` – Flask REST API consumed by the React GUI
- `gui/` – React + Vite dashboard (set `VITE_API_URL`)
- `modules/` – auto-fix helpers and dependency vulnerability scanner
- `security_checks/`, `analyzers/` – static-analysis rules
- `reports/` – PDF/Word/diagram generators
- `output/` – JSON/PDF report artifacts land here
- `test_all_functions.py` – examples and smoke tests

## Backend setup (CLI + API)

1) Install Python deps (core + PDF/report extras)  
`pip install flask flask-cors requests reportlab matplotlib psutil`

2) Quick CLI scan (JSON+PDF)  
`python comprehensive_analyzer.py test_project -both`  
Outputs are saved under `output/` (JSON always, PDF when `reportlab`/`matplotlib` are installed).

3) Run the REST API for the GUI  
`python analyzer_api.py` (binds to `http://0.0.0.0:5000`)  
Key endpoints: `/api/health`, `/api/start-analysis`, `/api/analysis/<id>/status`, `/api/analysis/<id>/download/{json|pdf}`

## Frontend (React dashboard)
1) `cd gui`  
2) Install deps: `npm install`  
3) Point the UI to the API (default falls back to `http://localhost:5000/api`):  
   - Set `VITE_API_URL=http://localhost:5000/api` (PowerShell: `$env:VITE_API_URL="http://localhost:5000/api"`).  
4) Start dev server: `npm run dev -- --host --port 5173`  
5) Open the printed URL, choose a project path, and start a scan. Downloads hit `/analysis/<id>/download/{json|pdf}`.

## Testing & smoke checks
- End-to-end smoke: `python test_all_functions.py`

## Tips & troubleshooting
- PDF missing? Install `reportlab` and `matplotlib`.  
- Dependency scans are faster/less rate-limited with `NVD_API_KEY` and `GITHUB_TOKEN`.  
- For large projects, expect longer runs; keep API server console open to watch progress logs.  
- Output paths default to `output/` (hard-coded to `D:\project\output` for PDFs on Windows).

