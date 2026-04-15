"""Session-priority ranking for analyst triage.

This module starts from an explainable heuristic policy, then optionally blends
in a persisted learned ranker when one is available. The heuristic path remains
the safety net so ranking stays stable even before any model is trained.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.config import cfg_path

try:
    import joblib
except Exception:  # pragma: no cover - optional dependency in some envs
    joblib = None


_SEVERITY_WEIGHT = {
    "CRITICAL": 20.0,
    "HIGH": 18.0,
    "MEDIUM": 12.0,
    "LOW": 6.0,
}

_RANKING_FEATURES = [
    "heuristic_priority",
    "confidence_pct",
    "anomaly_score",
    "cross_protocol_hops",
    "timer_anomaly_count",
    "dia_failure_count",
    "has_retransmission",
    "protocol_count",
    "technology_count",
    "message_count",
    "duration_ms",
    "unknown_label",
    "normal_label",
    "severity_weight",
    "agent_conflict",
    "pattern_similarity",
]

_MODEL_CACHE: dict[str, Any] = {"path": None, "payload": None}


def ranking_model_path() -> Path:
    configured = (
        cfg_path("model.ranking_path")
        or cfg_path("models.ranking")
        or "data/models/ranking_model.pkl"
    )
    return Path(configured)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _label_from_session(session: dict[str, Any], hybrid_rca: dict[str, Any]) -> str:
    return str(
        hybrid_rca.get("rca_label")
        or (session.get("hybrid_rca") or {}).get("rca_label")
        or (session.get("rca") or {}).get("rca_label")
        or session.get("rca_label")
        or "UNKNOWN"
    ).upper()


def heuristic_priority_score(
    session: dict,
    *,
    features: dict | None = None,
    intelligence: dict | None = None,
    hybrid_rca: dict | None = None,
    anomaly_result: dict | None = None,
    pattern_match: dict | None = None,
    confidence_model: dict | None = None,
) -> dict[str, Any]:
    """Return an explainable heuristic priority score for analyst triage."""
    features = features or session.get("features") or {}
    intelligence = intelligence or session.get("trace_intelligence") or {}
    hybrid_rca = hybrid_rca or session.get("hybrid_rca") or session.get("rca") or {}
    anomaly_result = anomaly_result or hybrid_rca.get("anomaly") or {}
    pattern_match = pattern_match or hybrid_rca.get("pattern_match") or {}
    confidence_model = confidence_model or hybrid_rca.get("confidence_model") or {}

    label = _label_from_session(session, hybrid_rca)
    severity = str(hybrid_rca.get("severity", "LOW")).upper()
    confidence_pct = _safe_float(hybrid_rca.get("confidence_pct", 0))
    anomaly_score = _safe_float(anomaly_result.get("score", 0))
    confidence_score = _safe_float(confidence_model.get("confidence_score", confidence_pct / 100.0))
    uncertainty = _safe_float(confidence_model.get("uncertainty", max(0.0, 1.0 - confidence_score)))
    similarity = _safe_float(pattern_match.get("similarity", 0))

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

    if _safe_float(features.get("timer_anomaly_count", 0)) > 0:
        score += min(6.0, _safe_float(features.get("timer_anomaly_count", 0)) * 1.5)
        reasons.append("timer anomalies")

    if _safe_float(features.get("has_retransmission", 0)):
        score += 5.0
        reasons.append("retransmissions")

    if _safe_float(features.get("dia_failure_count", 0)) > 0:
        score += min(8.0, _safe_float(features.get("dia_failure_count", 0)) * 2.0)
        reasons.append("Diameter failure")

    if _safe_float(features.get("cross_protocol_hops", 0)) >= 2:
        score += min(6.0, _safe_float(features.get("cross_protocol_hops", 0)) * 0.8)
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
        "priority_model_source": "heuristic",
    }


def build_priority_feature_row(
    session: dict[str, Any],
    *,
    features: dict | None = None,
    intelligence: dict | None = None,
    hybrid_rca: dict | None = None,
    anomaly_result: dict | None = None,
    pattern_match: dict | None = None,
    confidence_model: dict | None = None,
    heuristic: dict[str, Any] | None = None,
) -> dict[str, float]:
    features = features or session.get("features") or {}
    intelligence = intelligence or session.get("trace_intelligence") or {}
    hybrid_rca = hybrid_rca or session.get("hybrid_rca") or session.get("rca") or {}
    anomaly_result = anomaly_result or hybrid_rca.get("anomaly") or {}
    pattern_match = pattern_match or hybrid_rca.get("pattern_match") or {}
    confidence_model = confidence_model or hybrid_rca.get("confidence_model") or {}
    heuristic = heuristic or heuristic_priority_score(
        session,
        features=features,
        intelligence=intelligence,
        hybrid_rca=hybrid_rca,
        anomaly_result=anomaly_result,
        pattern_match=pattern_match,
        confidence_model=confidence_model,
    )

    label = _label_from_session(session, hybrid_rca)
    severity = str(hybrid_rca.get("severity", "LOW")).upper()
    message_count = (
        len(session.get("flow", []) or [])
        + len(session.get("sip_msgs", []) or [])
        + len(session.get("dia_msgs", []) or [])
        + len(session.get("inap_msgs", []) or [])
        + len(session.get("generic_msgs", []) or [])
        + len(session.get("gtp_msgs", []) or [])
    )

    return {
        "heuristic_priority": _safe_float(heuristic.get("priority_score", 0)),
        "confidence_pct": _safe_float(hybrid_rca.get("confidence_pct", 0)),
        "anomaly_score": _safe_float(anomaly_result.get("score", 0)),
        "cross_protocol_hops": _safe_float(features.get("cross_protocol_hops", 0)),
        "timer_anomaly_count": _safe_float(features.get("timer_anomaly_count", 0)),
        "dia_failure_count": _safe_float(features.get("dia_failure_count", 0)),
        "has_retransmission": _safe_float(features.get("has_retransmission", 0)),
        "protocol_count": float(len(session.get("protocols", []) or [])),
        "technology_count": float(len(session.get("technologies", []) or [])),
        "message_count": float(message_count),
        "duration_ms": _safe_float(session.get("duration_ms", 0)),
        "unknown_label": 1.0 if label == "UNKNOWN" else 0.0,
        "normal_label": 1.0 if label == "NORMAL_CALL" else 0.0,
        "severity_weight": _SEVERITY_WEIGHT.get(severity, 6.0),
        "agent_conflict": 1.0 if bool((session.get("autonomous_rca") or {}).get("agentic_analysis", {}).get("is_conflicted")) else 0.0,
        "pattern_similarity": _safe_float(pattern_match.get("similarity", 0)),
    }


def feature_names() -> list[str]:
    return list(_RANKING_FEATURES)


def _matrix_from_rows(rows: list[dict[str, float]], names: list[str]) -> list[list[float]]:
    return [[_safe_float(row.get(name, 0.0)) for name in names] for row in rows]


def load_ranker(model_path: str | Path | None = None) -> dict[str, Any] | None:
    target = Path(model_path or ranking_model_path())
    if not target.exists() or joblib is None:
        return None

    cache_key = str(target.resolve())
    if _MODEL_CACHE["path"] == cache_key:
        return _MODEL_CACHE["payload"]

    payload = joblib.load(target)
    if not isinstance(payload, dict) or "model" not in payload:
        return None

    _MODEL_CACHE["path"] = cache_key
    _MODEL_CACHE["payload"] = payload
    return payload


def clear_ranker_cache() -> None:
    _MODEL_CACHE["path"] = None
    _MODEL_CACHE["payload"] = None


def score_session_priority(
    session: dict,
    *,
    features: dict | None = None,
    intelligence: dict | None = None,
    hybrid_rca: dict | None = None,
    anomaly_result: dict | None = None,
    pattern_match: dict | None = None,
    confidence_model: dict | None = None,
    model_path: str | Path | None = None,
    use_model: bool = False,
) -> dict[str, Any]:
    """Return session priority, blending learned and heuristic scores when available."""
    heuristic = heuristic_priority_score(
        session,
        features=features,
        intelligence=intelligence,
        hybrid_rca=hybrid_rca,
        anomaly_result=anomaly_result,
        pattern_match=pattern_match,
        confidence_model=confidence_model,
    )
    if not use_model:
        return heuristic

    payload = load_ranker(model_path=model_path)
    if not payload:
        return heuristic

    names = payload.get("features") or feature_names()
    row = build_priority_feature_row(
        session,
        features=features,
        intelligence=intelligence,
        hybrid_rca=hybrid_rca,
        anomaly_result=anomaly_result,
        pattern_match=pattern_match,
        confidence_model=confidence_model,
        heuristic=heuristic,
    )
    matrix = _matrix_from_rows([row], names)
    model = payload["model"]
    predicted = _safe_float(model.predict(matrix)[0], heuristic["priority_score"])
    blended = max(0.0, min(99.0, (predicted * 0.7) + (_safe_float(heuristic["priority_score"]) * 0.3)))

    if blended >= 80:
        band = "critical"
    elif blended >= 60:
        band = "high"
    elif blended >= 35:
        band = "medium"
    else:
        band = "low"

    result = dict(heuristic)
    result["priority_score"] = round(blended, 1)
    result["priority_band"] = band
    result["priority_model_source"] = str(payload.get("model_type") or "learned")
    if result.get("priority_reason"):
        result["priority_reason"] = f"{result['priority_reason']}, learned triage support"
    else:
        result["priority_reason"] = "learned triage support"
    return result


def rank_sessions(sessions: list[dict]) -> list[dict]:
    """Return sessions sorted by descending triage priority."""
    return sorted(
        sessions,
        key=lambda session: (
            -_safe_float(session.get("priority_score", 0)),
            -_safe_float(
                (session.get("confidence") or session.get("hybrid_rca", {}) or {}).get("confidence_pct", 0)
                if isinstance(session.get("confidence"), dict)
                else session.get("confidence", 0) or session.get("hybrid_rca", {}).get("confidence_pct", 0)
            ),
            str(session.get("rca_label") or session.get("hybrid_rca", {}).get("rca_label") or ""),
        ),
    )
