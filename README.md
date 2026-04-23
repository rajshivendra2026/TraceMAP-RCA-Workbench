# TraceMAP RCA Workbench

TraceMAP RCA Workbench is a telecom packet-analysis and root-cause-analysis workbench for mixed IMS, packet-core, access, and transport captures. It ingests PCAP files, decodes protocol activity, correlates packets into end-to-end sessions, explains failure points, and presents the result in an analyst-friendly web dashboard.

The current release focuses on making the RCA path visible: selected session filters, correlation anchors, failure topology, evidence compaction, and a guided Demo Mode for walkthroughs.

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

Current app version: `v1.2.0`

Major upgrades in this release:

- Guided `Production` / `Demo` mode toggle.
- Demo Mode explanations for tabs, upload, filters, sessions, graphs, topology, learning, validation, and version history.
- Front-page Failure Topology with clickable nodes and edges.
- Light topology styling, no red failure state for normal sessions, draggable nodes, and automatic layout for larger node sets.
- Trace Briefing now reflects the selected session filter, such as `Call-ID`, `TEID`, `Diameter Session-ID`, `SEID`, `IMSI`, `MSISDN`, subscriber IP, or access UE IDs.
- RCA evidence compaction so repeated errors are shown once with a count.
- Learning moved into its own tab, with more dashboard space for analytics, Session RCA, and topology investigation.

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
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
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
