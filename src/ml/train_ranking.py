"""Training scaffold for learned analyst-priority ranking."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.config import cfg_path
from src.ml.ranking import score_session_priority

try:
    import joblib
except Exception:  # pragma: no cover - optional dependency in some envs
    joblib = None

try:
    import lightgbm as lgb
except Exception:  # pragma: no cover - optional dependency in some envs
    lgb = None


def ranking_model_path() -> Path:
    return Path(cfg_path("models.ranking", "data/models/ranking_model.pkl"))


def build_training_rows(sessions: list[dict[str, Any]]) -> tuple[list[dict[str, float]], list[float]]:
    rows: list[dict[str, float]] = []
    labels: list[float] = []
    for session in sessions:
        heuristic = score_session_priority(session)
        features = session.get("features") or {}
        rows.append(
            {
                "heuristic_priority": float(heuristic["priority_score"]),
                "confidence_pct": float((session.get("hybrid_rca") or session.get("rca") or {}).get("confidence_pct", 0) or 0),
                "anomaly_score": float(((session.get("hybrid_rca") or {}).get("anomaly") or {}).get("score", 0) or 0),
                "cross_protocol_hops": float(features.get("cross_protocol_hops", 0) or 0),
                "timer_anomaly_count": float(features.get("timer_anomaly_count", 0) or 0),
                "dia_failure_count": float(features.get("dia_failure_count", 0) or 0),
                "has_retransmission": float(features.get("has_retransmission", 0) or 0),
            }
        )
        labels.append(float(session.get("priority_label", heuristic["priority_score"])))
    return rows, labels


def train_ranking_model(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    rows, labels = build_training_rows(sessions)
    if lgb is None:
        return {
            "trained": False,
            "reason": "lightgbm_not_available",
            "row_count": len(rows),
        }

    feature_names = list(rows[0].keys()) if rows else []
    matrix = [[row[name] for name in feature_names] for row in rows]
    dataset = lgb.Dataset(matrix, label=labels, feature_name=feature_names)
    model = lgb.train(
        {
            "objective": "regression",
            "metric": "l2",
            "learning_rate": 0.05,
            "num_leaves": 31,
            "verbosity": -1,
        },
        dataset,
        num_boost_round=80,
    )
    if joblib is not None:
        target = ranking_model_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": model, "features": feature_names}, target)

    return {
        "trained": True,
        "row_count": len(rows),
        "feature_names": feature_names,
        "model_path": str(ranking_model_path()) if joblib is not None else None,
    }


def load_training_sessions(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Training session file must contain a list of sessions")
    return payload
