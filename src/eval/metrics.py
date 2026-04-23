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
    match_metrics = compute_expected_session_match_metrics(sessions, expected.get("expected_sessions") or [])
    return {
        **metrics,
        **match_metrics,
        "expected": expected,
    }


def compute_expected_session_match_metrics(
    sessions: list[dict[str, Any]],
    expected_sessions: list[dict[str, Any]],
) -> dict[str, Any]:
    if not expected_sessions:
        return {
            "expected_session_count": 0,
            "matched_expected_sessions": 0,
            "unexpected_session_count": 0,
            "session_precision": 0.0,
            "session_recall": 0.0,
            "session_f1": 0.0,
            "unmatched_expected_sessions": [],
        }

    unmatched_session_indexes = set(range(len(sessions)))
    matched_expected = 0
    unmatched_expected: list[str] = []

    for expected in expected_sessions:
        match_index = next(
            (
                index
                for index in list(unmatched_session_indexes)
                if _session_matches_expected(sessions[index], expected)
            ),
            None,
        )
        if match_index is None:
            unmatched_expected.append(str(expected.get("name") or expected.get("label") or expected.get("rca_label") or "expected_session"))
            continue
        matched_expected += 1
        unmatched_session_indexes.remove(match_index)

    expected_count = len(expected_sessions)
    predicted_count = len(sessions)
    precision = (matched_expected / predicted_count) if predicted_count else 0.0
    recall = (matched_expected / expected_count) if expected_count else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {
        "expected_session_count": expected_count,
        "matched_expected_sessions": matched_expected,
        "unexpected_session_count": max(0, predicted_count - matched_expected),
        "session_precision": round(precision, 4),
        "session_recall": round(recall, 4),
        "session_f1": round(f1, 4),
        "unmatched_expected_sessions": unmatched_expected,
    }


def _session_matches_expected(session: dict[str, Any], expected: dict[str, Any]) -> bool:
    label = expected.get("label") or expected.get("rca_label")
    if label and _session_label(session) != str(label).upper():
        return False

    required_protocols = {str(item).lower() for item in expected.get("required_protocols") or []}
    if required_protocols:
        protocols = {str(item).lower() for item in session.get("protocols", [])}
        if not required_protocols <= protocols:
            return False

    required_technologies = {str(item) for item in expected.get("required_technologies") or []}
    if required_technologies:
        technologies = {str(item) for item in session.get("technologies", [])}
        if not required_technologies <= technologies:
            return False

    required_methods = {str(item) for item in expected.get("required_correlation_methods") or []}
    if required_methods:
        methods = {str(item) for item in session.get("correlation_methods", [])}
        if not required_methods <= methods:
            return False

    anchors = expected.get("anchors") or {}
    for key, value in anchors.items():
        expected_value = str(value)
        if not _session_has_anchor(session, str(key), expected_value):
            return False

    return True


def _session_has_anchor(session: dict[str, Any], key: str, value: str) -> bool:
    candidates = {
        str(session.get(key) or ""),
        str(session.get(key.lower()) or ""),
    }
    for bucket in ("sip_msgs", "dia_msgs", "gtp_msgs", "generic_msgs", "pfcp_msgs", "http_msgs", "ikev2_msgs"):
        for message in session.get(bucket, []) or []:
            if not isinstance(message, dict):
                continue
            candidates.add(str(message.get(key) or ""))
            candidates.add(str(message.get(key.lower()) or ""))
    return value in candidates


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

    min_precision = expected.get("min_session_precision")
    if min_precision is not None and float(metrics.get("session_precision", 0.0)) < float(min_precision):
        reasons.append(f"session_precision {metrics.get('session_precision', 0.0):.4f} < {float(min_precision):.4f}")

    min_recall = expected.get("min_session_recall")
    if min_recall is not None and float(metrics.get("session_recall", 0.0)) < float(min_recall):
        reasons.append(f"session_recall {metrics.get('session_recall', 0.0):.4f} < {float(min_recall):.4f}")

    min_f1 = expected.get("min_session_f1")
    if min_f1 is not None and float(metrics.get("session_f1", 0.0)) < float(min_f1):
        reasons.append(f"session_f1 {metrics.get('session_f1', 0.0):.4f} < {float(min_f1):.4f}")

    max_unexpected = expected.get("max_unexpected_sessions")
    if max_unexpected is not None and int(metrics.get("unexpected_session_count", 0)) > int(max_unexpected):
        reasons.append(f"unexpected_session_count {metrics.get('unexpected_session_count', 0)} > {max_unexpected}")

    return (not reasons), reasons
