"""Retraining helpers driven by analyst validation feedback."""

from __future__ import annotations

from typing import Any

from src.config import cfg
from src.eval.drift import evaluate_feedback_drift
from src.eval.feedback_dataset import build_feedback_training_sessions, feedback_dataset_path

from .calibration import train_confidence_calibrator
from .promotion import (
    candidate_artifact_paths,
    compare_candidate_to_current,
    evaluate_artifact_set,
    promote_candidate_artifacts,
)
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

    drift = None
    if bool(cfg("learning.feedback_drift_detection_enabled", True)):
        drift = evaluate_feedback_drift(
            sessions,
            suite_path=cfg("autonomous.benchmark_suite", "benchmarks/expected_results.json"),
        )
        if not drift.get("passed"):
            return {
                "retrained": False,
                "reason": "feedback_drift_exceeds_limit",
                "sample_count": len(sessions),
                "min_samples": minimum,
                "dataset_path": target,
                "drift": drift,
            }

    candidate_paths = candidate_artifact_paths()
    candidate_paths["ranking"].parent.mkdir(parents=True, exist_ok=True)

    ranking = train_ranking_model(sessions, model_path=candidate_paths["ranking"])
    calibration = train_confidence_calibrator(sessions, model_path=candidate_paths["calibration"])

    promotion = None
    if bool(cfg("learning.feedback_promotion_enabled", True)):
        suite_path = cfg("autonomous.benchmark_suite", "benchmarks/expected_results.json")
        current_summary = evaluate_artifact_set(
            ranking_path=None,
            calibration_path=None,
            suite_path=suite_path,
        )
        candidate_summary = evaluate_artifact_set(
            ranking_path=candidate_paths["ranking"] if candidate_paths["ranking"].exists() else None,
            calibration_path=candidate_paths["calibration"] if candidate_paths["calibration"].exists() else None,
            suite_path=suite_path,
        )
        should_promote, reasons = compare_candidate_to_current(current_summary, candidate_summary)
        promoted_paths = {}
        if should_promote:
            promoted_paths = promote_candidate_artifacts(
                ranking_candidate_path=candidate_paths["ranking"] if candidate_paths["ranking"].exists() else None,
                calibration_candidate_path=candidate_paths["calibration"] if candidate_paths["calibration"].exists() else None,
            )
        promotion = {
            "evaluated": True,
            "promoted": bool(promoted_paths),
            "current": current_summary,
            "candidate": candidate_summary,
            "reasons": reasons,
            "promoted_paths": promoted_paths,
            "candidate_paths": {key: str(value) for key, value in candidate_paths.items()},
        }

    return {
        "retrained": bool(ranking.get("trained") or calibration.get("trained")),
        "sample_count": len(sessions),
        "min_samples": minimum,
        "dataset_path": target,
        "drift": drift,
        "ranking": ranking,
        "calibration": calibration,
        "promotion": promotion,
    }
