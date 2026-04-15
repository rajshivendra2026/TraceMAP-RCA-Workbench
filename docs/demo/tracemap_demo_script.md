# TraceMAP RCA Workbench Demo Script

## Purpose

This script is designed for a live product demo, technical walkthrough, customer workshop, or internal architecture review of TraceMAP RCA Workbench.

It explains:

- what the tool does
- how the GUI works
- how RCA is generated
- what value it adds over traditional packet analysis
- which use cases it best supports

## Recommended Demo Duration

- Short executive demo: `10-12 minutes`
- Technical operator demo: `20-30 minutes`
- Deep architecture and roadmap session: `35-45 minutes`

## Demo Objective

By the end of the demo, the audience should understand that TraceMAP RCA Workbench is not just a packet viewer. It is a telecom-native RCA system that:

- decodes multi-protocol traces
- correlates control-plane and service-plane activity into sessions
- labels probable root causes
- explains why a session failed or succeeded
- learns from new traces
- preserves and reuses that learning over time

## Demo Setup Checklist

Before the session:

- Confirm the app is running on `http://localhost:5050`
- Keep at least one successful trace and one failure trace ready
- Keep one inter-RAT or mobility-heavy trace ready if possible
- If demonstrating self-learning, keep a small folder of unseen PCAPs ready
- If demonstrating autonomous watcher mode, keep a second folder path available

Suggested demo trace mix:

- IMS voice or SIP + Diameter success trace
- SIP or Diameter failure trace
- LTE/5G mobility trace with `S1AP`, `NGAP`, `NAS_EPS`, `NAS_5GS`, `GTP`, or `SCTP`
- One noisy or imperfect trace to show resilience

## Demo Storyline

### Opening Narrative

Suggested talk track:

> Traditional packet analysis tools are good at decoding packets, filtering protocols, and helping experts inspect traces manually. The gap is that they stop before root-cause synthesis. TraceMAP RCA Workbench closes that gap for telecom workflows. It ingests mixed 2G, 3G, 4G, 5G, and IMS traces, correlates multi-protocol events into sessions, generates RCA, exposes evidence and confidence, and can continuously learn from new traces with gated knowledge updates.

## Walkthrough Script

### 1. Header And Entry Point

Point to the top bar in the GUI.

Explain:

- `Upload PCAP` is the primary analyst-driven intake path
- the filename indicator confirms the currently analyzed capture
- the UI is split into `Analysis` and `Visualization`

Value addition:

- simple intake path for operators
- no need to manually construct tshark commands just to start analysis

Suggested talk track:

> The top of the application is intentionally simple. Analysts can upload a PCAP directly, then move between a decision-oriented analysis view and a structure-oriented visualization view.

### 2. Session Explorer

Show the left sidebar.

Explain:

- `Session Explorer` is where the capture is reduced into correlated sessions
- filters support:
  - all vs failed vs success sessions
  - free-text search
  - protocol filtering
- each card shows:
  - session index
  - RCA label
  - SIP/final status where relevant
  - session or call identifier
  - protocol and technology chips

Value addition:

- moves the operator from packet-level hunting to session-level triage
- lets teams prioritize abnormal sessions immediately

Suggested talk track:

> Instead of scrolling through thousands of packets, we convert the trace into an analyst-ready session list. This is where the operator can immediately focus on failures, mobility slices, charging issues, or specific protocol families.

### 3. Trace Overview

Show the `Trace Overview` panel.

Explain:

- headline summarizes the overall capture
- supporting metadata describes likely call type, traffic character, and high-level trace nature
- the summary list gives immediate orientation before deep inspection

Value addition:

- shortens time-to-context for new analysts
- makes large mixed traces approachable quickly

Suggested talk track:

> This panel answers the first question an RCA engineer usually asks: what kind of trace is this and where should I start?

### 4. Expert Findings

Show the `Expert Findings` panel.

Explain:

- prioritizes likely issues in the current capture
- highlights probable starting points
- acts like an expert triage assistant

Value addition:

- gives immediate triage guidance
- reduces dependency on the most senior specialist just to get started

Suggested talk track:

> This is intentionally opinionated. Instead of asking the user to infer everything from raw traffic, the tool surfaces the most important investigative leads first.

### 5. Learning Control

Show the `Learning Control` panel.

Explain:

- `PCAP Learning Path` allows the analyst to define the folder used for learning
- `Save Path` persists the default learning folder for future runs
- `Start Learning` triggers folder-based learning from unseen PCAPs
- KPIs show:
  - unique patterns
  - learned PCAP count
  - new PCAPs pending
  - learning state
  - validation queue size

Value addition:

- turns the platform into a continuously improving RCA system
- supports analyst-driven or autonomous learning
- makes knowledge accumulation visible

Suggested talk track:

> This is one of the strongest differentiators of the platform. It is not only analyzing today’s trace. It can also absorb new trace patterns over time and refresh its RCA knowledge base in a controlled way.

### 6. Capture Analytics

Show the KPI area.

Explain:

- session count
- packet count
- protocol count
- technology count
- normal vs abnormal sessions
- average duration
- top RCA
- top protocol
- IMS, 2G/3G, LTE/4G, and 5G session counters
- transport issue counters

Value addition:

- gives operations teams a high-level summary immediately
- helps decide if the trace is service-layer, mobility-layer, or transport-layer heavy

Suggested talk track:

> These KPIs let you quickly classify the trace as an IMS issue, a radio/core mobility issue, or a transport-heavy issue before diving into session details.

### 7. Protocol And Endpoint Intelligence

Show the protocol and endpoint breakdowns.

Explain:

- protocol mix
- technology mix
- top endpoints
- RCA distribution

Value addition:

- reveals where activity is concentrated
- helps identify dominant nodes, interfaces, and failure clusters

Suggested talk track:

> This section helps answer whether the issue is distributed or concentrated. It also helps identify whether the trace is core-heavy, radio-heavy, or IMS-heavy.

### 8. Session RCA

Select a session and show the `Session RCA` panel.

Explain:

- title, summary, severity, confidence, and rule ID
- RCA narrative
- evidence list
- recommended next checks

Value addition:

- converts packet-level evidence into operator-facing RCA
- gives both explanation and actionability

Suggested talk track:

> This is where TraceMAP moves beyond decode into RCA. The tool provides not only the label, but also why it believes that label, how confident it is, and what the operator should check next.

### 9. Autonomous Reasoning

Show the `Autonomous Reasoning` panel.

Explain:

- protocol-agent votes
- causal chain
- confidence model
- knowledge signals from graph and time-series engines

Value addition:

- supplements deterministic rules with deeper reasoning
- helps explain edge cases, sparse traces, and repeated patterns
- gives transparency into why confidence changes

Suggested talk track:

> Rules remain the backbone, but the autonomous layer adds causal interpretation, specialist protocol hypotheses, and confidence calibration. This is especially useful in noisy or incomplete traces.

### 10. Details

Show the `Details` panel.

Explain:

- detailed session or trace context
- packet/event-level supporting information
- selected graph or ladder element details

Value addition:

- gives drill-down without forcing the user back into raw tshark output

### 11. Correlation

Show the `Correlation` panel.

Explain:

- strategy used for correlation
- technologies involved in the session

Value addition:

- makes session-building logic visible
- especially useful in multi-protocol telecom traces where correlation quality matters

Suggested talk track:

> In telecom RCA, wrong correlation means wrong RCA. This panel makes the session-binding logic visible and auditable.

### 12. Validation Queue

Show the `Validation Queue`.

Explain:

- uncertain or conflicted learning cases are queued here
- analyst can approve, reject, or defer
- this supports controlled learning instead of blind self-modification

Value addition:

- combines automation with operational safety
- creates a human-in-the-loop learning path where needed

Suggested talk track:

> The system can learn continuously, but it does not have to learn blindly. When confidence is weak or evidence conflicts, the trace can be held for human confirmation before pattern reinforcement.

### 13. Visualization Tab

Switch to `Visualization`.

Explain the three views:

- `Ladder View`
  - chronological message ladder
  - useful for procedure review and signaling inspection
- `Graph View`
  - endpoint and protocol topology
  - useful for node relationship and traffic shape
- `Causal View`
  - RCA-oriented event and cause chain
  - useful for explaining how the root cause was inferred

Value addition:

- supports different operator personas
- ladder view for protocol experts
- graph view for topology analysts
- causal view for RCA explainability

Suggested talk track:

> Different teams think differently. Some want chronological signaling, some want topology, and some want causality. The visualization tab supports all three perspectives.

### 14. Version History

Open the version or improvement history modal.

Explain:

- tracks product evolution and improvements
- useful for internal demos and release reviews

## How RCA Is Generated

This is the most important conceptual section of the demo.

Explain the RCA pipeline in this order:

1. The PCAP is decoded with `tshark`
2. Protocol-specific parsers normalize events
3. Events are correlated into sessions
4. Sessions are compacted and stitched if fragmented
5. Rule-based RCA assigns an initial label
6. Autonomous analysis adds:
   - agentic hypotheses
   - causal chain
   - confidence calibration
   - pattern similarity
   - anomaly context
7. Hybrid RCA blends these signals
8. The output is rendered with evidence and recommended next actions
9. Learning logic decides whether to:
   - reinforce a known pattern
   - add a candidate pattern
   - queue validation

Suggested talk track:

> RCA here is not a single model prediction. It is a layered decision process. Deterministic rules provide explainability, autonomous reasoning adds context, and learning allows the system to get stronger over time.

## Value Addition In RCA Generation

### Compared with a generic packet analyzer

- packet analyzers decode traffic; TraceMAP interprets telecom procedures
- packet analyzers expose data; TraceMAP produces RCA
- packet analyzers require more expert effort; TraceMAP shortens time-to-root-cause

### Compared with rule-only RCA

- rule-only systems struggle on sparse or unusual traces
- TraceMAP augments rules with learning, similarity, and autonomous reasoning

### Compared with black-box ML

- TraceMAP remains explainable
- evidence, causal chain, and validation queue remain visible
- the user can challenge or curate learning outcomes

## Possible Use Cases

### 1. IMS Voice Failure Triage

Use when:

- SIP call setup fails
- Diameter charging/authentication issues may be involved

Why TraceMAP helps:

- correlates SIP and Diameter
- surfaces charging vs network vs subscriber causes
- recommends next checks

### 2. 4G/5G Mobility And Handover RCA

Use when:

- `S1AP`, `NGAP`, `NAS_EPS`, `NAS_5GS`, `GTP`, or `SCTP` are involved
- mobility slices are fragmented
- inter-RAT failures are difficult to follow manually

Why TraceMAP helps:

- compacts and stitches fragmented mobility procedures
- reduces `UNKNOWN` sessions
- helps explain where the procedure broke

### 3. Charging Failure Investigation

Use when:

- Diameter `CCR/CCA` or policy/charging issues appear
- service succeeds at signaling level but fails commercially or session-wise

Why TraceMAP helps:

- highlights charging-path evidence
- preserves learned charging patterns

### 4. Subscriber And Authentication Problems

Use when:

- registration reject
- attach reject
- authorization or barring scenarios

Why TraceMAP helps:

- surfaces subscriber-barred and network-rejection patterns quickly

### 5. Cross-Team Incident Review

Use when:

- transport, IMS, radio, and core teams all need a common view

Why TraceMAP helps:

- ladder, graph, and causal views support different audiences
- the same session can be discussed from multiple perspectives

### 6. Continuous RCA Improvement In Lab Or Operations

Use when:

- teams receive new trace corpora regularly
- manual knowledge capture is inconsistent

Why TraceMAP helps:

- watcher discovers new traces
- learning refreshes seed intelligence
- gated git publishing keeps improvements portable

## Suggested Demo Closing

Suggested talk track:

> The main value of TraceMAP is that it turns telecom packet analysis into telecom root-cause analysis. It combines multi-protocol decoding, cross-session correlation, explainable RCA, autonomous reasoning, and controlled learning. That means less manual triage, faster investigation, reusable knowledge, and a platform that gets stronger with every new trace corpus.

## Q&A Talking Points

### If asked whether the tool replaces experts

Answer:

> No. It accelerates experts and reduces repetitive manual triage. It is designed to make specialists more effective, not remove them from the loop.

### If asked whether learning is safe

Answer:

> Learning is gated. The system can queue uncertain cases, hold operational review state, and publish only curated seed artifacts.

### If asked whether it supports new environments

Answer:

> Yes. The seed knowledge base is portable through git, and the tool can continue learning on a new machine while carrying over the current baseline.

## Presenter Notes

- Always start with one success trace before showing a failure trace
- Keep one mobility example ready if speaking to LTE/5G teams
- Show the validation queue if discussing safe autonomy
- Show the saved learning path if discussing continuous improvement
- Use the visualization tab when the audience is more network-topology oriented than protocol-message oriented
