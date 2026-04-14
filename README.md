# TraceMAP-RCA-Workbench

TraceMAP RCA Workbench is a telecom packet-analysis and root-cause-analysis workbench for mixed 2G/3G/4G/5G and IMS traces. It combines protocol parsing, session correlation, rule-based RCA, learning/knowledge reuse, and a lightweight web UI for inspecting captures and correlated sessions.

## Repository Layout

- [`/Users/shivendraraj/Downloads/Tool-2/src`](/Users/shivendraraj/Downloads/Tool-2/src) contains the core parsing, correlation, RCA, ML, and autonomous-analysis code.
- [`/Users/shivendraraj/Downloads/Tool-2/src/app`](/Users/shivendraraj/Downloads/Tool-2/src/app) contains the Flask app factory, summary helpers, and server-side runtime state helpers.
- [`/Users/shivendraraj/Downloads/Tool-2/tests`](/Users/shivendraraj/Downloads/Tool-2/tests) contains the regression and contract test suite.
- [`/Users/shivendraraj/Downloads/Tool-2/docs`](/Users/shivendraraj/Downloads/Tool-2/docs) contains architecture and runbook notes.
- [`/Users/shivendraraj/Downloads/Tool-2/data`](/Users/shivendraraj/Downloads/Tool-2/data) contains runtime inputs plus selected seed knowledge artifacts.

## Running Locally

Use the local virtual environment if present:

```bash
./venv/bin/python main.py
```

Run targeted tests with:

```bash
./venv/bin/python -m pytest -q
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
- `processed_sources.json`
- `timeseries_intelligence.json`
- `validation_queue.json`
- `vectors.json`

They are kept in git so a fresh clone starts with baseline RCA memory and supporting metadata rather than an empty knowledge store.

## Ignored Generated Data

The following are treated as local/generated runtime output and are ignored by git:

- `data/raw_pcaps/`
- `data/parsed/`
- `data/features/`
- `data/models/`
- `logs/`
- local virtual environment folders and cache artifacts
