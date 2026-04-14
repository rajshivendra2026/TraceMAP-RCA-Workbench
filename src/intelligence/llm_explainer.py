"""Human-readable RCA narratives without requiring an online LLM call."""

from __future__ import annotations


def build_llm_explanation(session: dict, hybrid_rca: dict, intelligence: dict) -> str:
    call_type = intelligence.get("call_type", "session")
    root = hybrid_rca.get("rca_title") or hybrid_rca.get("rca_label", "Unknown")
    summary = hybrid_rca.get("rca_summary") or "The session shows a protocol failure pattern."
    evidence = hybrid_rca.get("evidence", [])[:3]
    timing = intelligence.get("timer_anomalies", [])
    pattern = hybrid_rca.get("pattern_match") or {}

    lines = [f"{call_type} analysis indicates {root.lower()}: {summary}"]
    if evidence:
        lines.append("Key evidence: " + "; ".join(str(item) for item in evidence))
    if pattern.get("scenario"):
        lines.append(
            f"Historical similarity matched scenario '{pattern['scenario']}' "
            f"with similarity {round(float(pattern.get('similarity', 0)) * 100)}%."
        )
    if timing:
        lines.append("Timing anomalies observed: " + "; ".join(timing[:2]))
    return " ".join(lines)
