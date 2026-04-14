# Autonomous RCA Intelligence Architecture

```mermaid
flowchart LR
    A["PCAP Upload / Streaming Ingest"] --> B["TShark Extraction + Protocol Parsers"]
    B --> C["Normalized Packet Model"]
    C --> D["Session Correlation"]
    D --> E["Rule RCA"]
    D --> F["Feature Engineering + Embeddings"]
    D --> G["Protocol Agents"]
    D --> H["Causal Graph Engine"]
    F --> I["Pattern Similarity / Knowledge Engine"]
    G --> J["Agent Coordinator"]
    H --> K["Causal Inference"]
    E --> L["Confidence Engine"]
    I --> L
    J --> L
    K --> L
    F --> M["Anomaly Detection"]
    M --> L
    L --> N["Hybrid Autonomous RCA"]
    N --> O["UI Workbench"]
    N --> P["Active Learning Loop"]
    P --> Q["Validation Queue"]
    P --> R["Knowledge Graph"]
    P --> S["Pattern Store + Vector Store"]
    P --> T["Time-Series Intelligence"]
    P --> U["Skill Export"]
```

## Key Design Outcomes

- Rule-based RCA remains the explainable backbone.
- Protocol agents add specialist hypotheses without breaking the shared RCA contract.
- Causal inference adds chain reasoning beyond direct pattern matching.
- Confidence is calibrated from multiple transparent sources.
- Knowledge evolves into both reusable patterns and a structured graph.
- Time-series intelligence helps distinguish transient and recurring failures.
- The same autonomous stack supports batch and real-time processing.
