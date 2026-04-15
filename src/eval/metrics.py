"""Metrics used by benchmark and quality-gate evaluation."""

from __future__ import annotations

from collections import Counter
from typing import Any


def _session_label(session: dict[str, Any]) -> str:
    rca = session.get("rca") or {}
    hybrid = session.get("hybrid_rca") or {}
    return str(
        rca.get("rca_label")
        or hybrid.get("rca_label")
        or session.get("rca_label")
        or "UNKNOWN"
    ).upper()


def compute_session_metrics(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    label_counts = Counter(_session_label(session) for session in sessions)
    session_count = len(sessions)
    unknown_count = int(label_counts.get("UNKNOWN", 0))
    abnormal_count = sum(count for label, count in label_counts.items() if label != "NORMAL_CALL")
    top_priority = max(
        (float(session.get("priority_score", 0) or 0) for session in sessions),
        default=0.0,
    )
    return {
        "session_count": session_count,
        "label_counts": dict(label_counts),
        "unknown_count": unknown_count,
        "unknown_ratio": round((unknown_count / session_count) if session_count else 0.0, 4),
        "abnormal_count": abnormal_count,
        "top_label": label_counts.most_common(1)[0][0] if label_counts else "UNKNOWN",
        "top_priority_score": round(top_priority, 2),
    }


def compute_case_metrics(
    sessions: list[dict[str, Any]],
    expected: dict[str, Any],
) -> dict[str, Any]:
    metrics = compute_session_metrics(sessions)
    return {
        **metrics,
        "expected": expected,
    }


def benchmark_case_passed(
    metrics: dict[str, Any],
    expected: dict[str, Any],
) -> tuple[bool, list[str]]:
    reasons: list[str] = []

    min_sessions = expected.get("min_session_count")
    if min_sessions is not None and int(metrics["session_count"]) < int(min_sessions):
        reasons.append(f"session_count {metrics['session_count']} < {min_sessions}")

    max_unknown = expected.get("max_unknown")
    if max_unknown is not None and int(metrics["unknown_count"]) > int(max_unknown):
        reasons.append(f"unknown_count {metrics['unknown_count']} > {max_unknown}")

    max_unknown_ratio = expected.get("max_unknown_ratio")
    if max_unknown_ratio is not None and float(metrics["unknown_ratio"]) > float(max_unknown_ratio):
        reasons.append(f"unknown_ratio {metrics['unknown_ratio']:.4f} > {float(max_unknown_ratio):.4f}")

    required_labels = expected.get("required_labels") or {}
    for label, minimum in required_labels.items():
        actual = int(metrics["label_counts"].get(str(label).upper(), 0))
        if actual < int(minimum):
            reasons.append(f"label {label} count {actual} < {minimum}")

    dominant_label = expected.get("dominant_label")
    if dominant_label and str(metrics["top_label"]).upper() != str(dominant_label).upper():
        reasons.append(f"top_label {metrics['top_label']} != {dominant_label}")

    return (not reasons), reasons
