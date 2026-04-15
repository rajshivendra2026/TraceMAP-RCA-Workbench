"""Session-priority ranking for analyst triage.

This module intentionally starts with an explainable scoring policy so the UI
can benefit from ranking immediately. The interface is model-friendly: a future
trained ranker can replace the internals without changing callers.
"""

from __future__ import annotations

from typing import Any


_SEVERITY_WEIGHT = {
    "CRITICAL": 20.0,
    "HIGH": 18.0,
    "MEDIUM": 12.0,
    "LOW": 6.0,
}


def score_session_priority(
    session: dict,
    *,
    features: dict | None = None,
    intelligence: dict | None = None,
    hybrid_rca: dict | None = None,
    anomaly_result: dict | None = None,
    pattern_match: dict | None = None,
    confidence_model: dict | None = None,
) -> dict[str, Any]:
    """Return an explainable session-priority score for analyst triage."""
    features = features or session.get("features") or {}
    intelligence = intelligence or session.get("trace_intelligence") or {}
    hybrid_rca = hybrid_rca or session.get("hybrid_rca") or session.get("rca") or {}
    anomaly_result = anomaly_result or hybrid_rca.get("anomaly") or {}
    pattern_match = pattern_match or hybrid_rca.get("pattern_match") or {}
    confidence_model = confidence_model or hybrid_rca.get("confidence_model") or {}

    label = str(hybrid_rca.get("rca_label", "UNKNOWN")).upper()
    severity = str(hybrid_rca.get("severity", "LOW")).upper()
    confidence_pct = float(hybrid_rca.get("confidence_pct", 0) or 0)
    anomaly_score = float(anomaly_result.get("score", 0) or 0)
    confidence_score = float(confidence_model.get("confidence_score", confidence_pct / 100.0) or 0)
    uncertainty = float(confidence_model.get("uncertainty", max(0.0, 1.0 - confidence_score)) or 0)
    similarity = float(pattern_match.get("similarity", 0) or 0)

    score = 10.0
    reasons: list[str] = []

    if label != "NORMAL_CALL":
        score += 30.0
        reasons.append(f"{label.replace('_', ' ').title()} RCA")
    if label == "UNKNOWN":
        score += 16.0
        reasons.append("needs correlation review")

    severity_bonus = _SEVERITY_WEIGHT.get(severity, 6.0)
    if label != "NORMAL_CALL" or severity in {"HIGH", "CRITICAL"}:
        score += severity_bonus
        if severity in {"HIGH", "CRITICAL"}:
            reasons.append(f"{severity.title()} severity")

    if label != "NORMAL_CALL":
        score += min(18.0, confidence_pct * 0.16)
    else:
        score += min(8.0, max(0.0, (100.0 - confidence_pct) * 0.08))

    if anomaly_score >= 0.55:
        score += min(12.0, anomaly_score * 12.0)
        reasons.append("anomalous behavior")

    if uncertainty >= 0.35:
        score += min(10.0, uncertainty * 14.0)
        reasons.append("low confidence")

    if bool((session.get("autonomous_rca") or {}).get("agentic_analysis", {}).get("is_conflicted")):
        score += 8.0
        reasons.append("agent disagreement")

    if float(features.get("timer_anomaly_count", 0) or 0) > 0:
        score += min(6.0, float(features.get("timer_anomaly_count", 0)) * 1.5)
        reasons.append("timer anomalies")

    if float(features.get("has_retransmission", 0) or 0):
        score += 5.0
        reasons.append("retransmissions")

    if float(features.get("dia_failure_count", 0) or 0) > 0:
        score += min(8.0, float(features.get("dia_failure_count", 0)) * 2.0)
        reasons.append("Diameter failure")

    if float(features.get("cross_protocol_hops", 0) or 0) >= 2:
        score += min(6.0, float(features.get("cross_protocol_hops", 0)) * 0.8)
        reasons.append("cross-protocol complexity")

    if similarity >= 0.92 and label == "NORMAL_CALL":
        score -= 8.0
    elif similarity >= 0.92:
        score += 4.0

    score = max(0.0, min(99.0, score))
    if score >= 80:
        band = "critical"
    elif score >= 60:
        band = "high"
    elif score >= 35:
        band = "medium"
    else:
        band = "low"

    ordered_reasons = []
    seen = set()
    for reason in reasons:
        if reason in seen:
            continue
        seen.add(reason)
        ordered_reasons.append(reason)

    return {
        "priority_score": round(score, 1),
        "priority_band": band,
        "priority_reason": ", ".join(ordered_reasons[:3]) or "baseline inspection",
    }


def rank_sessions(sessions: list[dict]) -> list[dict]:
    """Return sessions sorted by descending triage priority."""
    return sorted(
        sessions,
        key=lambda session: (
            -float(session.get("priority_score", 0) or 0),
            -float((session.get("confidence") or session.get("hybrid_rca", {}) or {}).get("confidence_pct", 0) if isinstance(session.get("confidence"), dict) else session.get("confidence", 0) or session.get("hybrid_rca", {}).get("confidence_pct", 0) or 0),
            str(session.get("rca_label") or session.get("hybrid_rca", {}).get("rca_label") or ""),
        ),
    )
