"""Anomaly ensemble helpers for telecom session signals."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

try:  # pragma: no cover - optional dependency
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover - dependency may be unavailable
    IsolationForest = None


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def build_anomaly_feature_row(
    session: dict[str, Any],
    *,
    features: dict[str, Any] | None = None,
    intelligence: dict[str, Any] | None = None,
) -> dict[str, float]:
    features = features or session.get("features") or {}
    intelligence = intelligence or session.get("trace_intelligence") or {}
    protocols = {str(item).upper() for item in (session.get("protocols") or [])}
    technologies = {str(item).upper() for item in (session.get("technologies") or [])}
    label = str((session.get("hybrid_rca") or session.get("rca") or {}).get("rca_label", "UNKNOWN")).upper()

    return {
        "duration_ms": _safe_float(features.get("duration_ms", session.get("duration_ms", 0))),
        "time_to_failure_ms": _safe_float(features.get("time_to_failure_ms", session.get("time_to_failure_ms", 0))),
        "cross_protocol_hops": _safe_float(features.get("cross_protocol_hops", 0)),
        "timer_anomaly_count": _safe_float(features.get("timer_anomaly_count", 0)),
        "has_retransmission": _safe_float(features.get("has_retransmission", 0)),
        "dia_failure_count": _safe_float(features.get("dia_failure_count", 0)),
        "charging_failed": _safe_float(features.get("charging_failed", 0)),
        "auth_failed_dia": _safe_float(features.get("auth_failed_dia", 0)),
        "sip_error_count": _safe_float(features.get("sip_4xx", 0)) + _safe_float(features.get("sip_5xx", 0)),
        "network_fail_q850": _safe_float(features.get("q850_network_fail", 0)),
        "protocol_count": float(len(protocols)),
        "technology_count": float(len(technologies)),
        "sequence_length": _safe_float(intelligence.get("sequence_length", 0)),
        "is_mobility_trace": 1.0 if protocols.intersection({"S1AP", "NGAP", "RANAP", "NAS_EPS", "NAS_5GS", "GTP", "PFCP"}) else 0.0,
        "is_transport_heavy": 1.0 if "TRANSPORT" in technologies or protocols.intersection({"TCP", "UDP", "SCTP"}) else 0.0,
        "is_unknown": 1.0 if label == "UNKNOWN" else 0.0,
    }


def anomaly_feature_names() -> list[str]:
    return [
        "duration_ms",
        "time_to_failure_ms",
        "cross_protocol_hops",
        "timer_anomaly_count",
        "has_retransmission",
        "dia_failure_count",
        "charging_failed",
        "auth_failed_dia",
        "sip_error_count",
        "network_fail_q850",
        "protocol_count",
        "technology_count",
        "sequence_length",
        "is_mobility_trace",
        "is_transport_heavy",
        "is_unknown",
    ]


def _matrix_from_rows(rows: list[dict[str, float]]) -> list[list[float]]:
    names = anomaly_feature_names()
    return [[_safe_float(row.get(name, 0.0)) for name in names] for row in rows]


def _suggested_root_cause(session: dict[str, Any], features: dict[str, Any]) -> str:
    current = str((session.get("hybrid_rca") or session.get("rca") or {}).get("rca_label", "UNKNOWN")).upper()
    if _safe_float(features.get("charging_failed", 0)) or _safe_float(features.get("dia_failure_count", 0)) >= 2:
        return "CHARGING_FAILURE"
    if _safe_float(features.get("auth_failed_dia", 0)):
        return "SUBSCRIBER_BARRED"
    if _safe_float(features.get("q850_network_fail", 0)) or _safe_float(features.get("has_retransmission", 0)):
        return "CORE_NETWORK_FAILURE"
    if _safe_float(features.get("cross_protocol_hops", 0)) >= 3 and _safe_float(features.get("timer_anomaly_count", 0)) >= 2:
        return "NETWORK_CONGESTION"
    return current


def _signal_breakdown(row: dict[str, float]) -> dict[str, float]:
    transport = min(
        1.0,
        (
            (row["has_retransmission"] * 0.45)
            + (min(row["timer_anomaly_count"], 4.0) * 0.12)
            + (row["network_fail_q850"] * 0.22)
            + (row["is_transport_heavy"] * 0.08)
        ),
    )
    charging = min(
        1.0,
        (
            (min(row["dia_failure_count"], 4.0) * 0.2)
            + (row["charging_failed"] * 0.34)
            + (row["auth_failed_dia"] * 0.24)
        ),
    )
    signaling = min(
        1.0,
        (
            (min(row["sip_error_count"], 4.0) * 0.16)
            + (min(row["cross_protocol_hops"], 6.0) * 0.08)
            + (min(row["sequence_length"], 24.0) / 120.0)
            + (row["is_unknown"] * 0.18)
        ),
    )
    mobility = min(
        1.0,
        (
            (row["is_mobility_trace"] * 0.16)
            + (min(row["cross_protocol_hops"], 6.0) * 0.06)
            + (min(row["timer_anomaly_count"], 4.0) * 0.06)
            + (row["technology_count"] * 0.02)
        ),
    )
    return {
        "transport": round(transport, 4),
        "charging": round(charging, 4),
        "signaling": round(signaling, 4),
        "mobility": round(mobility, 4),
    }


@dataclass
class AnomalyEnsemble:
    """Blend deterministic telecom anomaly signals with optional detectors."""

    detectors: list[object] = field(default_factory=list)

    def fit(self, rows: Iterable[list[float]]) -> "AnomalyEnsemble":
        data = list(rows)
        for detector in self.detectors:
            fit = getattr(detector, "fit", None)
            if callable(fit):
                fit(data)
        return self

    def score_rows(self, rows: Iterable[list[float]]) -> list[float]:
        data = list(rows)
        if not self.detectors:
            return [0.0 for _ in data]

        blended: list[float] = []
        for row in data:
            values: list[float] = []
            for detector in self.detectors:
                if hasattr(detector, "score_samples"):
                    raw = detector.score_samples([row])
                    values.append(max(0.0, min(1.0, float(-raw[0]))))
                elif hasattr(detector, "decision_function"):
                    raw = detector.decision_function([row])
                    values.append(max(0.0, min(1.0, float(raw[0]))))
                elif hasattr(detector, "predict_proba"):
                    raw = detector.predict_proba([row])
                    values.append(max(0.0, min(1.0, float(raw[0][-1]))))
            blended.append(round(sum(values) / len(values), 4) if values else 0.0)
        return blended


def score_session_anomaly(
    session: dict[str, Any],
    *,
    features: dict[str, Any] | None = None,
    intelligence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    features = features or session.get("features") or {}
    intelligence = intelligence or session.get("trace_intelligence") or {}
    row = build_anomaly_feature_row(session, features=features, intelligence=intelligence)
    breakdown = _signal_breakdown(row)

    model_score = 0.0
    if IsolationForest is not None:  # pragma: no branch - optional dependency
        try:
            model = IsolationForest(random_state=42, contamination=0.18)
            matrix = _matrix_from_rows(
                [
                    row,
                    {**row, "timer_anomaly_count": max(0.0, row["timer_anomaly_count"] - 1.0), "has_retransmission": 0.0},
                    {**row, "cross_protocol_hops": max(0.0, row["cross_protocol_hops"] - 1.0), "dia_failure_count": max(0.0, row["dia_failure_count"] - 1.0)},
                    {key: 0.0 for key in anomaly_feature_names()},
                ]
            )
            model.fit(matrix)
            model_score = max(0.0, min(1.0, float(-model.score_samples([matrix[0]])[0])))
        except Exception:
            model_score = 0.0

    weighted = (
        (breakdown["transport"] * 0.28)
        + (breakdown["charging"] * 0.32)
        + (breakdown["signaling"] * 0.22)
        + (breakdown["mobility"] * 0.18)
    )
    score = max(0.0, min(1.0, (weighted * 0.82) + (model_score * 0.18)))
    dominant_signal = max(breakdown.items(), key=lambda item: item[1])[0]

    return {
        "score": round(score, 4),
        "is_anomalous": bool(score >= 0.55),
        "suggested_root_cause": _suggested_root_cause(session, features),
        "signals": list(intelligence.get("timer_anomalies", [])[:3]),
        "component_scores": breakdown,
        "dominant_signal": dominant_signal,
        "model_score": round(model_score, 4),
        "model_type": "ensemble",
    }
