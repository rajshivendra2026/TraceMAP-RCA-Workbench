# Autonomous RCA Repository Analysis

This document maps proven ideas from production observability and packet-analysis systems into the TraceMAP RCA platform.

## Comparative Analysis

| Repository | Relevant reusable concept | Current gap in TraceMAP | Integration plan |
| --- | --- | --- | --- |
| Wireshark | Protocol-dissector discipline, layered field extraction, protocol registration | We parse many protocols, but we still rely on a flatter normalized model with less explicit layered event semantics | Use Wireshark-style per-protocol event semantics in the causal graph and protocol agents. Preserve multi-layer packets as separate causal events instead of flattening them. |
| Arkime | Session-centric indexing, parser/plugin loading, long-retention searchable session metadata | We have persistent pattern storage, but session/search intelligence is still lighter than a true investigation index | Treat correlated sessions as first-class indexed objects, persist richer graph/session metadata, and maintain reusable protocol/plugin boundaries for future parsers. |
| Zeek | Event-driven analyzers, protocol intelligence from analyzer outputs, dynamic analyzer enablement | We correlate sessions after parsing, but we lack a clean event bus for higher-order reasoning | Promote normalized packet flow into event nodes and feed agentic RCA and causal inference off those event streams. |
| Jaeger | Trace/span correlation, causal service-path view, root-cause exploration across hops | We have ladder/graph and sessions, but no explicit causal chain model across events | Model protocol messages as spans/events with weighted edges, then infer root causes using multi-hop propagation like trace analysis. |
| OpenTelemetry | Receivers → processors → exporters pipeline, standardization, low-coupling telemetry flow | The current pipeline is strong but still application-specific and less modular for streaming | Adopt receiver/processor/exporter-style stages for batch and real-time RCA so parsing, enrichment, reasoning, and export remain composable. |
| PyOD | Practical anomaly-detection model library, isolation/outlier focus | We have a lightweight anomaly path, but it is not yet a pluggable anomaly subsystem | Keep fast heuristic default, but expose a clean anomaly engine interface compatible with Isolation Forest and future PyOD-style models. |
| DeepLog | Sequence-aware anomaly detection from ordered events using LSTM sequence modeling | We extract sequence signatures, but sequence reasoning is still heuristic | Preserve ordered protocol signatures so an LSTM/sequence model can be added later without redesigning the session contract. |
| Kats | Cross-trace time-series analysis, recurrence, change-point and anomaly analytics | We reason mainly within a single trace, not over longitudinal behavior | Persist RCA/time-series observations across traces and detect recurring or periodic failure patterns. |

## Integration Notes Per Repository

### Wireshark

- Relevant source: [Wireshark Developer's Guide, dissector chapter](https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html)
- Reusable idea:
  Wireshark’s dissector model treats each protocol layer as a structured contributor to a packet tree rather than collapsing packets into one opaque record.
- Integration:
  We mirror that by turning normalized ladder events into explicit causal graph nodes and by preserving protocol-layer detail for agentic RCA.

### Arkime

- Relevant source: [Arkime settings and capture/session model](https://arkime.com/settings)
- Reusable idea:
  Arkime emphasizes session tracking, parser modularity, and searchable retained metadata.
- Integration:
  We extend our knowledge layer from flat reusable patterns into persistent session-oriented graph memory and graph-backed RCA evidence.

### Zeek

- Relevant source: [Zeek analyzer framework](https://docs.zeek.org/en/v7.0.10/scripts/base/frameworks/analyzer/)
- Reusable idea:
  Zeek protocol analyzers emit events that downstream logic consumes for detection and intelligence.
- Integration:
  Our protocol agents and causal engine consume normalized session events in the same spirit, enabling telecom-aware multi-agent analysis.

### Jaeger

- Relevant source: [Jaeger architecture](https://www.jaegertracing.io/docs/latest/architecture/)
- Reusable idea:
  Distributed tracing models system behavior as causally connected spans collected, stored, and visualized end to end.
- Integration:
  We adapt that to packet/session RCA by treating protocol events like spans in a causal chain and scoring upstream/downstream dependencies.

### OpenTelemetry

- Relevant source: [OpenTelemetry Collector architecture](https://opentelemetry.io/docs/collector/architecture/)
- Reusable idea:
  Receivers, processors, and exporters form a clean and scalable telemetry pipeline.
- Integration:
  Our batch and streaming RCA paths now align to parse/normalize, enrich/reason, learn/persist phases with minimal coupling.

### PyOD

- Relevant source: [PyOD documentation](https://pyod.readthedocs.io/en/latest/)
- Reusable idea:
  Practical anomaly-detection interfaces make it easy to swap models without changing the wider system contract.
- Integration:
  We keep anomaly detection modular and optional so low-latency deployments can stay lightweight while still supporting future model upgrades.

### DeepLog

- Relevant source: [DeepLog README summarizing the LSTM approach](https://github.com/Thijsvanede/DeepLog/blob/master/README.md)
- Reusable idea:
  Ordered event sequences are powerful supervision signals for anomaly detection and online monitoring.
- Integration:
  We preserve ordered telecom sequence signatures and causal event order so deeper sequence models can be added later without schema churn.

### Kats

- Relevant source: [Kats overview](https://facebookresearch.github.io/Kats/)
- Reusable idea:
  Time-series detection, forecasting, and feature extraction help distinguish one-off faults from recurring systemic issues.
- Integration:
  We added a time-series intelligence engine that records cross-trace RCA observations and surfaces recurring failure signatures.
