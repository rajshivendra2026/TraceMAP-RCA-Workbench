"""Retraining helpers driven by analyst validation feedback."""

from __future__ import annotations

from typing import Any

from src.config import cfg
from src.eval.feedback_dataset import build_feedback_training_sessions, feedback_dataset_path

from .calibration import train_confidence_calibrator
from .train_ranking import train_ranking_model


def retrain_from_feedback(
    *,
    dataset_path: str | None = None,
    min_samples: int | None = None,
) -> dict[str, Any]:
    target = dataset_path or str(feedback_dataset_path())
    sessions = build_feedback_training_sessions(target)
    minimum = int(min_samples if min_samples is not None else cfg("learning.feedback_min_samples", 3))

    if len(sessions) < minimum:
        return {
            "retrained": False,
            "reason": "insufficient_feedback_samples",
            "sample_count": len(sessions),
            "min_samples": minimum,
            "dataset_path": target,
        }

    ranking = train_ranking_model(sessions)
    calibration = train_confidence_calibrator(sessions)
    return {
        "retrained": bool(ranking.get("trained") or calibration.get("trained")),
        "sample_count": len(sessions),
        "min_samples": minimum,
        "dataset_path": target,
        "ranking": ranking,
        "calibration": calibration,
    }
