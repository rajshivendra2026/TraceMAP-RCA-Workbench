# TraceMAP-RCA-Workbench

TraceMAP RCA Workbench is a telecom packet-analysis and root-cause-analysis workbench for mixed 2G/3G/4G/5G and IMS traces. It combines protocol parsing, session correlation, rule-based RCA, learning/knowledge reuse, and a lightweight web UI for inspecting captures and correlated sessions.

## Quick Start

macOS or Linux:

```bash
git clone https://github.com/rajshivendra2026/TraceMAP-RCA-Workbench.git
cd TraceMAP-RCA-Workbench
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

Windows PowerShell:

```powershell
git clone https://github.com/rajshivendra2026/TraceMAP-RCA-Workbench.git
cd TraceMAP-RCA-Workbench
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

Open:

```text
http://localhost:5050
```

## Repository Layout

- [`/Users/shivendraraj/Downloads/Tool-2/src`](/Users/shivendraraj/Downloads/Tool-2/src) contains the core parsing, correlation, RCA, ML, and autonomous-analysis code.
- [`/Users/shivendraraj/Downloads/Tool-2/src/app`](/Users/shivendraraj/Downloads/Tool-2/src/app) contains the Flask app factory, summary helpers, and server-side runtime state helpers.
- [`/Users/shivendraraj/Downloads/Tool-2/tests`](/Users/shivendraraj/Downloads/Tool-2/tests) contains the regression and contract test suite.
- [`/Users/shivendraraj/Downloads/Tool-2/docs`](/Users/shivendraraj/Downloads/Tool-2/docs) contains architecture and runbook notes.
- [`/Users/shivendraraj/Downloads/Tool-2/data`](/Users/shivendraraj/Downloads/Tool-2/data) contains runtime inputs plus selected seed knowledge artifacts.

## Running Locally

Use the local virtual environment if present:

```bash
python main.py
```

Run targeted tests with:

```bash
python -m pytest -q
```

Run the autonomous watcher once:

```bash
python -m src.autonomous.watcher --once
```

Run the autonomous watcher continuously:

```bash
python -m src.autonomous.watcher --interval 60
```

Serve the app with Waitress instead of the compatibility launcher:

```bash
waitress-serve --host=0.0.0.0 --port=5050 wsgi:app
```

## Important Commands

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the web UI:

```bash
python main.py
```

Run the full test suite:

```bash
python -m pytest -q
```

Run focused autonomy tests:

```bash
python -m pytest tests/test_autonomous_watcher.py -q
```

Run one supervised learning cycle:

```bash
python -m src.autonomous.watcher --once
```

Run continuous autonomous learning:

```bash
python -m src.autonomous.watcher --interval 60
```

Trigger a manual git sync after local work:

```bash
git add .
git commit -m "Describe your change"
git push origin main
```

## Windows Setup

Recommended baseline:

- Windows 11
- Python `3.11`
- Git for Windows
- Wireshark with `tshark`

After installing Wireshark, confirm `tshark.exe` exists at:

```text
C:\Program Files\Wireshark\tshark.exe
```

If auto-detection does not pick it up, set the environment variable in PowerShell before running the app:

```powershell
$env:TC_RCA__TSHARK__BINARY="C:\Program Files\Wireshark\tshark.exe"
```

To avoid Matplotlib cache warnings on locked-down Windows profiles, set:

```powershell
$env:MPLCONFIGDIR="$PWD\.cache\matplotlib"
```

Then run:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

## Configure a New Machine From Git

1. Clone the repository.
2. Create and activate a Python `3.11` virtual environment.
3. Install dependencies from [`/Users/shivendraraj/Downloads/Tool-2/requirements.txt`](/Users/shivendraraj/Downloads/Tool-2/requirements.txt).
4. Install Wireshark or `tshark`.
5. Start the app with `python main.py`.
6. Run `python -m src.autonomous.watcher --once` to validate the learning path.

Suggested first-run sequence on a new machine:

```bash
git clone https://github.com/rajshivendra2026/TraceMAP-RCA-Workbench.git
cd TraceMAP-RCA-Workbench
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/test_autonomous_watcher.py -q
python main.py
```

Suggested first-run sequence on Windows PowerShell:

```powershell
git clone https://github.com/rajshivendra2026/TraceMAP-RCA-Workbench.git
cd TraceMAP-RCA-Workbench
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest tests/test_autonomous_watcher.py -q
python main.py
```

If you want the new machine to treat all local traces as unseen, clear the watcher state before starting autonomous learning:

```bash
rm -f data/knowledge_base/processed_sources.json
```

Windows PowerShell equivalent:

```powershell
Remove-Item data\knowledge_base\processed_sources.json -ErrorAction SilentlyContinue
```

If you also want a clean analyst-review queue on the new machine, optionally clear:

```bash
rm -f data/knowledge_base/validation_queue.json
rm -rf data/knowledge_base/run_reports
```

Windows PowerShell equivalent:

```powershell
Remove-Item data\knowledge_base\validation_queue.json -ErrorAction SilentlyContinue
Remove-Item data\knowledge_base\run_reports -Recurse -Force -ErrorAction SilentlyContinue
```

## Docker

The app can run in Docker, including the `tshark` dependency used for PCAP decoding.

Build and start it with:

```bash
docker compose up --build
```

Then open:

```text
http://localhost:5050
```

Container details:

- [`/Users/shivendraraj/Downloads/Tool-2/Dockerfile`](/Users/shivendraraj/Downloads/Tool-2/Dockerfile) installs Python dependencies and `tshark`, then serves the app with `waitress`.
- [`/Users/shivendraraj/Downloads/Tool-2/docker-compose.yml`](/Users/shivendraraj/Downloads/Tool-2/docker-compose.yml) maps port `5050` and mounts runtime directories for uploaded PCAPs, parsed outputs, features, models, and logs.
- `data/knowledge_base/` stays baked into the image as tracked seed data.

Notes:

- Uploaded or learned runtime outputs under `data/raw_pcaps/`, `data/parsed/`, `data/features/`, `data/models/`, and `logs/` are mounted from the host in `docker-compose.yml`.
- If you want completely ephemeral container runs, remove those volume mounts.
- The container sets `TC_RCA__TSHARK__BINARY=/usr/bin/tshark` so the app does not rely on host Wireshark paths.

## Remote Access

There are four supported remote-access paths documented in [`/Users/shivendraraj/Downloads/Tool-2/docs/remote_access.md`](/Users/shivendraraj/Downloads/Tool-2/docs/remote_access.md):

1. Tailscale for private access from anywhere
2. Cloudflare Tunnel for public HTTPS without opening ports
3. Caddy for HTTPS reverse proxy on a server or VM
4. [`/Users/shivendraraj/Downloads/Tool-2/docker-compose.prod.yml`](/Users/shivendraraj/Downloads/Tool-2/docker-compose.prod.yml) as the production deployment baseline

## Seed Knowledge Base

The files under [`/Users/shivendraraj/Downloads/Tool-2/data/knowledge_base`](/Users/shivendraraj/Downloads/Tool-2/data/knowledge_base) are intentionally tracked as seed data.

These files provide a starting knowledge layer for the RCA engine and learning flows, including:

- `knowledge_graph.json`
- `metrics.json`
- `patterns.json`
- `timeseries_intelligence.json`
- `vectors.json`

They are kept in git so a fresh clone starts with baseline RCA memory and supporting metadata rather than an empty knowledge store.

The following knowledge-base files are operational state and may be reset per machine if you want a clean local intake history:

- `processed_sources.json`
- `validation_queue.json`
- `run_reports/`

## Ignored Generated Data

The following are treated as local/generated runtime output and are ignored by git:

- `data/raw_pcaps/`
- `data/parsed/`
- `data/features/`
- `data/models/`
- `logs/`
- local virtual environment folders and cache artifacts
