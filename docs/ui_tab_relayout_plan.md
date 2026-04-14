# UI Tab Relayout Plan

## Goal

Reduce information overload by separating "what happened", "why it failed", and "where to inspect packets" into distinct analyst workflows.

## Proposed Top-Level Tabs

### 1. Overview
- Trace summary headline
- Expert findings
- Key KPIs only
- Top RCA and top protocol
- Technology / protocol mix
- Learning status strip

### 2. Sessions
- Session explorer and filters
- Session list
- Session summary card
- Correlation summary
- Session-specific key facts:
  - A-party / B-party
  - IMSI / MSISDN
  - Protocols
  - Technologies
  - Duration

### 3. RCA
- RCA title, confidence, severity, rule ID
- Detailed narrative
- Evidence
- Recommended next checks
- Historical pattern match / anomaly notes
- Session-specific failure timeline summary

### 4. Call Flow
- Ladder view
- Graph view
- Shared interaction detail panel
- Protocol toggles
- Message hover / packet evidence

### 5. Protocol Detail
- Per-protocol raw breakdown for selected session
- Diameter details:
  - command names
  - result codes
  - request / answer role
  - session IDs
- SIP / MAP / NAS / HTTP equivalents where present

### 6. Learning
- Learning path input
- Learned pattern count
- Learned PCAP count
- Pending PCAP count
- Last learning run status
- Validation queue / review count

### 7. Version / History
- Version number
- Improvement history
- Known limitations / residual parser gaps

## Layout Principles

- Keep trace-wide information separate from selected-session information.
- Treat RCA as a narrative workspace, not a KPI dump.
- Keep ladder and graph in a dedicated inspection tab.
- Reserve raw protocol detail for deep-dive troubleshooting.
- Avoid showing more than one dense grid on screen at a time.

## Suggested Default Navigation

1. `Overview` after upload
2. `Sessions` to choose the conversation
3. `RCA` to understand failure classification
4. `Call Flow` to inspect sequence and packet evidence
5. `Protocol Detail` only when deeper validation is needed
