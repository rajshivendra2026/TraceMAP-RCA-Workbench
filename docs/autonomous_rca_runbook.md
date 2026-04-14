# Autonomous RCA Runbook

## Sample Execution Flow

1. A PCAP is uploaded or a parsed micro-batch arrives through the streaming ingest layer.
2. Packet extraction and protocol parsing produce normalized telecom events.
3. Session correlation groups events across protocols into one investigation unit.
4. Rule RCA generates the baseline explainable diagnosis.
5. Protocol agents analyze the same session in parallel and emit local RCA hypotheses.
6. The causal graph engine converts ordered flow into event nodes and weighted edges.
7. Causal inference scores the chain and identifies likely upstream fault contributors.
8. Pattern similarity and anomaly scoring enrich the evidence set.
9. The confidence engine calibrates the final RCA outcome.
10. The learning loop updates patterns, the knowledge graph, and cross-trace time-series intelligence.
11. If the decision is uncertain or conflicting, the session is routed to validation instead of being blindly reinforced.

## Knowledge Graph Example

```json
{
  "nodes": {
    "protocol:diameter": {"type": "protocol", "name": "DIAMETER"},
    "event:diameter-saa-5003": {"type": "event", "name": "DIAMETER:SAA 5003"},
    "error:subscriber-barred": {"type": "error", "name": "SUBSCRIBER_BARRED"},
    "scenario:subscriber-barred": {"type": "scenario", "name": "Subscriber Barred"}
  },
  "edges": {
    "scenario:subscriber-barred|contains|event:diameter-saa-5003": {"relation": "contains"},
    "event:diameter-saa-5003|correlates_with|error:subscriber-barred": {"relation": "correlates_with"},
    "protocol:diameter|participates_in|scenario:subscriber-barred": {"relation": "participates_in"}
  }
}
```

## Agent Interaction Example

```text
Diameter Agent  -> SUBSCRIBER_BARRED (0.90) because Diameter auth was rejected
NAS Agent       -> NETWORK_REJECTION (0.84) because Registration Reject followed
Transport Agent -> NORMAL_CALL (0.35) because transport had no dominant failure

Coordinator:
- top hypothesis: SUBSCRIBER_BARRED
- consensus score: 0.58
- conflict flag: false
```

## Deployment Strategy

### Batch mode

- Use the existing PCAP pipeline for offline RCA, training, and knowledge reinforcement.
- Enable compaction and skill export after large learning runs.
- Best for historical backfill, model bootstrapping, and RCA quality measurement.

### Real-time mode

- Feed parsed protocol events into the streaming ingest abstraction.
- Flush micro-batches into the real-time RCA pipeline.
- Keep validation enabled and compaction off the hot path.
- Best for near-real-time fault triage with bounded latency.

## Operational Notes

- Rule RCA remains authoritative for explainability.
- Agentic and causal reasoning refine, not replace, the baseline diagnosis.
- Validation protects the knowledge base from drift when confidence is weak or experts disagree.
