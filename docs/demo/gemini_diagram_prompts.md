# Gemini Prompts For Architecture And Workflow Diagrams

Use these prompts in Gemini when you want polished architecture and workflow diagrams for TraceMAP RCA Workbench.

## Prompt 1: Architecture Diagram

Create a polished enterprise architecture diagram for a telecom analytics product called **TraceMAP RCA Workbench**.

The diagram should be in a modern product-architecture style suitable for a technical presentation slide. Use a clean white or very light background, sharp boxes, clear arrows, subtle telecom-themed color coding, and professional typography.

The diagram must show these major layers from left to right:

1. **Input Layer**
   - Raw PCAP / PCAPNG traces
   - Upload UI
   - Watched learning folder

2. **Decode Layer**
   - tshark extraction
   - packet normalization

3. **Protocol Parser Layer**
   - SIP
   - Diameter
   - INAP
   - NGAP
   - S1AP
   - RANAP
   - MAP
   - NAS_EPS
   - NAS_5GS
   - GTP
   - PFCP
   - TCP
   - UDP
   - SCTP

4. **Correlation Layer**
   - Session correlation
   - session compaction
   - procedure-state stitching
   - transport-noise suppression

5. **RCA Layer**
   - rule-based RCA
   - evidence extraction
   - severity and confidence
   - recommended next checks

6. **Autonomous Intelligence Layer**
   - protocol agents
   - causal inference
   - confidence model
   - knowledge graph signals
   - time-series intelligence

7. **Learning Layer**
   - pattern similarity
   - vector memory
   - candidate patterns
   - reinforcement
   - validation queue

8. **Persistence Layer**
   - patterns.json
   - vectors.json
   - knowledge_graph.json
   - metrics.json
   - timeseries_intelligence.json

9. **Operations Layer**
   - analyst UI
   - autonomous watcher
   - gated seed refresh
   - git auto-commit / auto-push

Important visual requirements:

- Use directional arrows to show information flow
- Show that the analyst UI consumes RCA output and validation queue data
- Show that the autonomous watcher consumes new traces and updates the persistence layer
- Show that gated publish sits between learning and git
- Make the diagram visually balanced and presentation-ready
- Include the title: **TraceMAP RCA Workbench Architecture**
- Include a short subtitle: **Telecom packet decoding, session correlation, RCA, and autonomous learning**

## Prompt 2: Workflow Diagram

Create a detailed workflow diagram for **TraceMAP RCA Workbench** showing how a new telecom PCAP is processed from ingestion to RCA and autonomous learning.

The diagram should be a clear process flow suitable for an engineering or customer presentation. Use a vertical or left-to-right flow with decision diamonds where appropriate.

The exact workflow should be:

1. New trace arrives
2. Decode with tshark
3. Parse protocol-specific fields
4. Normalize packet events
5. Correlate events into sessions
6. Compact fragmented sessions
7. Stitch mobility and inter-RAT procedures
8. Suppress SCTP heartbeat and transport noise
9. Apply rule-based RCA
10. Run autonomous reasoning
11. Blend hybrid RCA
12. Render analyst-facing RCA output
13. Update knowledge graph, vectors, metrics, and patterns
14. Generate run summary report
15. Evaluate gates:
    - did curated seed files change
    - is UNKNOWN ratio acceptable
    - did validation queue grow within limit
    - is pattern count stable
16. If gates pass:
    - create curated git commit
    - push to remote repository
17. If gates fail:
    - hold changes for review
    - keep run report and validation evidence

Also show:

- analyst validation queue as a side branch for uncertain cases
- saved learning path / watched folder feeding the autonomous watcher
- UI display of RCA, evidence, confidence, and validation queue

Design requirements:

- use a modern enterprise workflow style
- use color coding for ingestion, analysis, learning, and publication stages
- clearly distinguish normal flow from review/hold flow
- include the title: **TraceMAP RCA Workbench Workflow**
- include a subtitle: **From PCAP ingestion to gated autonomous knowledge refresh**

## Prompt 3: GUI Feature Map

Create a clean annotated product UI explainer diagram for **TraceMAP RCA Workbench**.

The goal is to show the major GUI areas and what each one does. The layout should resemble a modern telecom analytics dashboard.

Annotate these regions:

- top header with upload action
- tabs for Analysis and Visualization
- left sidebar Session Explorer with filters
- Trace Overview
- Expert Findings
- Learning Control
- Capture Analytics KPI section
- Protocol And Endpoint Intelligence
- Session RCA
- Autonomous Reasoning
- Details
- Correlation
- Validation Queue
- Visualization views:
  - Ladder View
  - Graph View
  - Causal View

For each region, add a short label describing its value in RCA generation.

Make it presentation-ready, structured, and easy to understand for both product and technical audiences.
