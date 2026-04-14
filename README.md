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
