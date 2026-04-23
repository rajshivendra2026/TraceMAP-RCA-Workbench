# TraceMAP RCA Workbench

TraceMAP RCA Workbench is a telecom packet-analysis and root-cause-analysis workbench for mixed IMS, packet-core, access, and transport captures. It ingests PCAP files, decodes protocol activity, correlates packets into end-to-end sessions, explains failure points, and presents the result in an analyst-friendly web dashboard.

The current release focuses on 5G and VoWiFi correlation maturity: stronger SBI SUPI/GPSI/SUCI extraction, safer ePDG inner/outer IP fusion, subscriber-conflict protection, and the production-readiness foundations from the prior release.

![TraceMAP architecture and flow](docs/assets/tracemap_overview.svg)

## What It Does

- Upload and analyze `.pcap`, `.pcapng`, and `.cap` telecom traces from the browser.
- Decode and normalize multi-protocol traffic with `tshark` plus project-specific enrichment.
- Build correlated sessions across IMS, Diameter, GTP, PFCP, access, and transport traffic.
- Identify call/session outcomes, RCA signals, repeated error causes, and likely break points.
- Render Trace Overview, Trace Briefing, Capture Analytics, Session RCA, Failure Topology, protocol views, and graph/ladder/causal views.
- Maintain a self-learning knowledge base with validation, drift checks, candidate model promotion, and optional autonomous watcher workflows.
- Support Production Mode for quiet operations and Demo Mode for detailed in-product explanations.

## Latest Release

Current app version: `v1.4.0`

Major upgrades in this release:

- Expanded 5G SBI extraction across HTTP/2 headers, decoded hex payloads, JSON scalar fields, SUPI, concealed SUCI, GPSI, tel URI, and MSISDN variants.
- Stronger 5G session seeding through SBI/NAS-5GS subscriber identity instead of falling back only to stream or transaction IDs.
- VoWiFi/ePDG inner/outer IP fusion now supports decoded IKE inner-IP lists, IKE NAI IMSI/MSISDN extraction, and conservative automatic alias inference.
- Added subscriber-conflict protection to prevent endpoint-only false merges when different IMSIs or UE/framed IPs share the same core nodes.
- Cisco-inspired cyan/blue visual refresh with colored navigation markers and stronger operator scanability.
- Section-specific accents for Trace Overview, Trace Briefing, Capture Analytics, Session RCA, Failure Topology, and correlation panels.
- Color-coded KPI cards and protocol chips for faster SIP/Diameter/GTP/access/transport scanning.
- Release Health panel with app version, git branch/commit, readiness score, tshark compatibility, writable runtime checks, and operator actions.
- System health API plus CLI preflight for stale branch, dirty product files, missing tshark, unsupported fields, auth posture, and runtime directory issues.
- Windows setup and run scripts for repeatable laptop bootstrap.
- CI-ready smoke coverage for Linux and Windows; the workflow file remains on the feature branch until the GitHub token has `workflow` scope.
- Generated sample PCAP smoke test that exercises the real tshark parser path.
- IKE/ePDG compatibility checks aligned with the ISAKMP-backed parser mode.

Full version history is stored in [docs/version_history.json](docs/version_history.json).

## Session Correlation Model

TraceMAP uses an identity-led correlation model first, then enriches it with state and causal overlays where the capture provides enough evidence.

Primary anchors:

- `SIP`: `Call-ID`, parties, dialog metadata, contact/Via/source context.
- `Diameter`: `Session-Id`, `IMSI`, `MSISDN`, `APN`, `Framed-IP`.
- `GTP/GTPv2`: `TEID`, `F-TEID`, subscriber IP, `IMSI`, bearer/session context.
- `PFCP`: `SEID`, peer tuple, session endpoint context.
- `S1AP/NGAP/NAS`: UE/access identifiers, control-plane procedure context, stream/transaction information.
- `TCP/UDP/SCTP`: flow tuple and stream context when no stronger telecom identity is available.

Important behavior:

- Time is used as a safety boundary and supporting signal, not as the primary join key.
- `correlation.fallback_time_only` is disabled by default in `config.yaml`.
- Hard identity matches carry higher confidence than heuristic or fallback matches.
- The UI exposes the selected filter and correlation anchors so reviewers can see why a session was grouped.

## RCA And Visualization

The dashboard is built around investigation flow:

- `Trace Overview`: capture type, parties, protocols, technologies, session count, and health summary.
- `Trace Briefing`: selected-session filter, correlation anchors, call/session briefing, and capture context.
- `Capture Analytics`: protocol mix, message activity, status distribution, and capture-level signals.
- `Session RCA`: analyst narrative, priority, severity, confidence, evidence, and recommended next checks.
- `Failure Topology`: clickable service/path topology showing implicated nodes, break edges, and selected-node details.
- `Protocol Audit`: protocol and endpoint-level inspection.
- `Visualization`: ladder, graph, and causal graph views.
- `Learning`: knowledge-base status, learning path, validation queue, and feedback actions.
- `Validation`: analyst validation workflow for model and knowledge feedback.

## Production Mode vs Demo Mode

`Production Mode` keeps the interface quiet for live analysis.

`Demo Mode` turns on guided explanations. Hover, focus, or click supported UI items to see what the item shows, why it matters, and how TraceMAP derives it. This is intended for customer walkthroughs, reviews, demos, and onboarding.

The mode is stored in the browser so analysts can keep their preferred behavior between sessions.

## Supported Protocol Areas

The project includes parsing, normalization, or correlation logic across these protocol families:

- IMS and SIP signaling.
- Diameter subscriber/auth/charging context.
- GTP/GTPv2 control and user-plane tunnel context.
- PFCP/N4 session endpoint context.
- NAS EPS and NAS 5GS control-plane context.
- S1AP, NGAP, RANAP, MAP, INAP, RADIUS.
- TCP, UDP, SCTP, and generic transport context.

Coverage depends on what is present and decodable in the uploaded capture. Partial captures may produce lower confidence sessions or require analyst validation.

## Requirements

Recommended local baseline:

- Python `3.11`
- Git
- Wireshark or standalone `tshark`
- Modern browser

The app can still start without `tshark`, but PCAP decoding and protocol extraction require it.

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
.\scripts\setup_windows.ps1
.\scripts\run_windows.ps1
```

Open the workbench:

```text
http://localhost:5050
```

## Common Commands

Run the web app:

```bash
python main.py
```

Run the test suite:

```bash
python -m pytest -q
```

Run production preflight:

```bash
python scripts/preflight.py
```

Run the generated sample-PCAP parser smoke test:

```bash
python -m pytest -q tests/test_ci_smoke_pcap.py
```

Run focused summary/UI-support tests:

```bash
python -m unittest tests.test_trace_summary
```

Run one autonomous learning cycle:

```bash
python -m src.autonomous.watcher --once
```

Run continuous autonomous learning:

```bash
python -m src.autonomous.watcher --interval 60
```

Serve through Waitress directly:

```bash
waitress-serve --host=0.0.0.0 --port=5050 wsgi:app
```

## Release Health And Preflight

The dashboard includes a `Release Health` panel on the front page. It shows the running app version, git branch, commit, readiness score, Python runtime, tshark version, IKE/ePDG compatibility mode, writable runtime paths, and recommended operator actions.

The same checks are available from the CLI:

```bash
python scripts/preflight.py
python scripts/preflight.py --json
python scripts/preflight.py --strict
```

Use `--strict` in release gates when warnings should block deployment.

The health API is available at:

```text
http://localhost:5050/health
http://localhost:5050/api/system-health
```

## TShark Setup

TraceMAP uses `tshark` for PCAP field extraction.

macOS with Homebrew:

```bash
brew install wireshark
```

Linux:

```bash
sudo apt-get update
sudo apt-get install -y tshark
```

Windows:

- Install Wireshark.
- Confirm `tshark.exe` exists at `C:\Program Files\Wireshark\tshark.exe`.
- Or let the bootstrap script attempt installation:

```powershell
.\scripts\setup_windows.ps1 -InstallTshark
```

- If auto-detection does not find it, set:

```powershell
$env:TC_RCA__TSHARK__BINARY="C:\Program Files\Wireshark\tshark.exe"
```

For locked-down profiles, set a writable Matplotlib cache directory:

```powershell
$env:MPLCONFIGDIR="$PWD\.cache\matplotlib"
```

## Configuration

Runtime settings live in [config.yaml](config.yaml).

Common settings:

- `server.port`: web UI port, default `5050`.
- `server.max_upload_mb`: upload size limit.
- `tshark.binary`: `auto` or explicit `tshark` path.
- `correlation.window_sec`: time window used as a guardrail.
- `correlation.fallback_time_only`: keep `false` for production-grade identity-led correlation.
- `learning.*`: feedback, drift detection, candidate promotion, and knowledge-doctor settings.
- `autonomous.*`: watcher paths, benchmark gates, optional auto-commit, and optional push branch.

Environment variables can override config values using the `TC_RCA__SECTION__KEY` form. Example:

```bash
TC_RCA__SERVER__PORT=5051 python main.py
```

## Repository Layout

```text
.
|-- css/                     Browser styling
|-- js/                      Dashboard interactions and rendering
|-- src/app/                 Flask app, routes, summaries, UI-facing state
|-- src/correlation/         Session correlation and merge logic
|-- src/parser/              PCAP and protocol extraction helpers
|-- src/intelligence/        Knowledge, vector, learning, and RCA intelligence
|-- src/autonomous/          Autonomous watcher and RCA workflows
|-- tests/                   Regression and contract tests
|-- docs/                    Architecture, runbooks, demos, version history
|-- data/knowledge_base/     Tracked seed knowledge plus local runtime state
`-- config.yaml              Runtime configuration
```

## Learning And Knowledge Base

TraceMAP ships with seed knowledge in `data/knowledge_base` so a fresh clone starts with baseline RCA memory.

Tracked seed-style artifacts include:

- `knowledge_graph.json`
- `metrics.json`
- `patterns.json`
- `timeseries_intelligence.json`
- `vectors.json`

Operational state may change during local runs:

- `processed_sources.json`
- `validation_queue.json`
- `run_reports/`

Do not blindly commit operational churn unless you intentionally want to publish updated learning state.

## CI

CI smoke coverage is implemented in the test suite and the workflow template is prepared on the feature branch. Publishing `.github/workflows/ci.yml` requires a GitHub token with `workflow` scope.

The intended CI gate runs on Linux and Windows:

- Installs Python dependencies.
- Installs Wireshark/tshark.
- Runs production preflight.
- Runs the full test suite.
- Runs a generated sample PCAP smoke test through the real parser path.

## Docker

Build and start:

```bash
docker compose up --build
```

Open:

```text
http://localhost:5050
```

Docker notes:

- [Dockerfile](Dockerfile) installs Python dependencies and `tshark`.
- [docker-compose.yml](docker-compose.yml) maps port `5050`.
- Runtime directories are mounted from the host where configured by compose.
- The container sets `TC_RCA__TSHARK__BINARY=/usr/bin/tshark`.

## Remote Access

Remote deployment options are documented in [docs/remote_access.md](docs/remote_access.md), including:

- Tailscale private access.
- Cloudflare Tunnel.
- Caddy reverse proxy.
- Production Docker Compose baseline.

## Demo Assets

- [Presenter script](docs/demo/tracemap_demo_script.md)
- [Word-openable handout](docs/demo/TraceMAP_Demo_Script.rtf)
- [Gemini diagram prompt pack](docs/demo/gemini_diagram_prompts.md)

## Testing Notes

Recommended before pushing code:

```bash
python -m pytest -q
node --check js/events.js
node --check js/render.js
node --check js/state.js
python -m json.tool docs/version_history.json
```

If only the Trace Briefing, RCA summary, or Failure Topology changed:

```bash
python -m unittest tests.test_trace_summary
```

## Git Hygiene

Before committing, check the worktree:

```bash
git status --short
```

Prefer staging intentional files only:

```bash
git add README.md
git commit -m "Update README for current TraceMAP release"
git push origin main
```

Avoid `git add .` when local learning runs have changed large knowledge-base operational files.

## Current Limitations

- Correlation quality depends on available decoded identities in the capture.
- Partial captures can miss access-plane or subscriber-plane attachment.
- SIP forking, deep 5G SBI JSON parsing, and advanced mobility stitching are areas for continued hardening.
- Heuristic joins should be reviewed through the displayed correlation anchors and confidence signals.

## License

No license file is currently included. Add one before public redistribution or external reuse.
