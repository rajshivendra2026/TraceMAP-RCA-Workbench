"""Metrics used by benchmark and quality-gate evaluation."""

from __future__ import annotations

from collections import Counter
from typing import Any


def _session_label(session: dict[str, Any]) -> str:
    hybrid = session.get("hybrid_rca") or {}
    rca = session.get("rca") or {}
    return str(
        hybrid.get("rca_label")
        or rca.get("rca_label")
        or session.get("rca_label")
        or "UNKNOWN"
    ).upper()


def compute_session_metrics(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    label_counts = Counter(_session_label(session) for session in sessions)
    correlation_method_counts = Counter()
    session_count = len(sessions)
    unknown_count = int(label_counts.get("UNKNOWN", 0))
    abnormal_count = sum(count for label, count in label_counts.items() if label != "NORMAL_CALL")
    identity_correlated_sessions = 0
    stateful_correlated_sessions = 0
    time_fallback_sessions = 0
    priority_scores = [float(session.get("priority_score", 0) or 0) for session in sessions]
    abnormal_priorities = [
        float(session.get("priority_score", 0) or 0)
        for session in sessions
        if _session_label(session) != "NORMAL_CALL"
    ]
    confidence_scores = [
        float(
            session.get("confidence")
            or (session.get("hybrid_rca") or {}).get("confidence_pct")
            or (session.get("rca") or {}).get("confidence_pct")
            or 0
        )
        for session in sessions
    ]
    for session in sessions:
        methods = {str(method) for method in session.get("correlation_methods", []) if method}
        correlation_method_counts.update(methods)
        if any(method.startswith("identity:") for method in methods):
            identity_correlated_sessions += 1
        if any(method.startswith("state:") for method in methods):
            stateful_correlated_sessions += 1
        dia_strategy = str(session.get("dia_correlation") or "").lower()
        gtp_strategy = str(session.get("gtp_correlation") or "").lower()
        if (
            any("time_cluster" in method or "time_only" in method for method in methods)
            or "time_cluster" in dia_strategy
            or "time_cluster" in gtp_strategy
            or "time_only" in dia_strategy
            or "time_only" in gtp_strategy
        ):
            time_fallback_sessions += 1
    top_priority = max(
        priority_scores,
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
        "avg_priority_score": round((sum(priority_scores) / len(priority_scores)) if priority_scores else 0.0, 2),
        "avg_abnormal_priority_score": round((sum(abnormal_priorities) / len(abnormal_priorities)) if abnormal_priorities else 0.0, 2),
        "avg_confidence_pct": round((sum(confidence_scores) / len(confidence_scores)) if confidence_scores else 0.0, 2),
        "correlation_method_counts": dict(correlation_method_counts),
        "identity_correlated_sessions": identity_correlated_sessions,
        "stateful_correlated_sessions": stateful_correlated_sessions,
        "time_fallback_sessions": time_fallback_sessions,
        "avg_correlation_method_count": round(
            (
                sum(len(session.get("correlation_methods", []) or []) for session in sessions)
                / len(sessions)
            )
            if sessions
            else 0.0,
            2,
        ),
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

    min_identity = expected.get("min_identity_correlated_sessions")
    if min_identity is not None and int(metrics.get("identity_correlated_sessions", 0)) < int(min_identity):
        reasons.append(f"identity_correlated_sessions {metrics.get('identity_correlated_sessions', 0)} < {min_identity}")

    min_stateful = expected.get("min_stateful_correlated_sessions")
    if min_stateful is not None and int(metrics.get("stateful_correlated_sessions", 0)) < int(min_stateful):
        reasons.append(f"stateful_correlated_sessions {metrics.get('stateful_correlated_sessions', 0)} < {min_stateful}")

    max_time_fallback = expected.get("max_time_fallback_sessions")
    if max_time_fallback is not None and int(metrics.get("time_fallback_sessions", 0)) > int(max_time_fallback):
        reasons.append(f"time_fallback_sessions {metrics.get('time_fallback_sessions', 0)} > {max_time_fallback}")

    required_methods = expected.get("required_correlation_methods") or {}
    method_counts = metrics.get("correlation_method_counts") or {}
    for method, minimum in required_methods.items():
        actual = int(method_counts.get(str(method), 0))
        if actual < int(minimum):
            reasons.append(f"correlation method {method} count {actual} < {minimum}")

    return (not reasons), reasons
