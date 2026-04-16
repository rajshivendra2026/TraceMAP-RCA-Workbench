"""Model promotion and drift-aware benchmark gating for learned artifacts."""

from __future__ import annotations

import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from src.config import cfg, cfg_path
from src.eval.benchmark_runner import run_benchmark_suite

from .calibration import calibration_model_path, clear_calibrator_cache
from .ranking import clear_ranker_cache, ranking_model_path


def candidate_model_dir() -> Path:
    configured = cfg_path("learning.feedback_candidate_dir", "data/models/candidates")
    return Path(configured)


def candidate_artifact_paths() -> dict[str, Path]:
    base = candidate_model_dir()
    return {
        "ranking": base / "ranking_model.candidate.pkl",
        "calibration": base / "confidence_calibrator.candidate.pkl",
    }


@contextmanager
def using_model_artifacts(
    *,
    ranking_path: str | Path | None = None,
    calibration_path: str | Path | None = None,
) -> Iterator[None]:
    old_ranking = os.environ.get("TC_RCA__MODEL__RANKING_PATH")
    old_calibration = os.environ.get("TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH")
    try:
        if ranking_path is not None:
            os.environ["TC_RCA__MODEL__RANKING_PATH"] = str(ranking_path)
        elif "TC_RCA__MODEL__RANKING_PATH" in os.environ:
            del os.environ["TC_RCA__MODEL__RANKING_PATH"]

        if calibration_path is not None:
            os.environ["TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH"] = str(calibration_path)
        elif "TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH" in os.environ:
            del os.environ["TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH"]

        clear_ranker_cache()
        clear_calibrator_cache()
        yield
    finally:
        if old_ranking is None:
            os.environ.pop("TC_RCA__MODEL__RANKING_PATH", None)
        else:
            os.environ["TC_RCA__MODEL__RANKING_PATH"] = old_ranking

        if old_calibration is None:
            os.environ.pop("TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH", None)
        else:
            os.environ["TC_RCA__MODEL__CONFIDENCE_CALIBRATION_PATH"] = old_calibration

        clear_ranker_cache()
        clear_calibrator_cache()


def evaluate_artifact_set(
    *,
    ranking_path: str | Path | None,
    calibration_path: str | Path | None,
    suite_path: str | Path | None = None,
) -> dict[str, Any]:
    with using_model_artifacts(ranking_path=ranking_path, calibration_path=calibration_path):
        report = run_benchmark_suite(suite_path=suite_path)
    return summarize_benchmark_report(report)


def summarize_benchmark_report(report: dict[str, Any]) -> dict[str, Any]:
    cases = report.get("cases") or []
    metrics = [case.get("metrics") or {} for case in cases if isinstance(case.get("metrics"), dict)]
    avg_abnormal_priority = (
        sum(float(item.get("avg_abnormal_priority_score", 0) or 0) for item in metrics) / len(metrics)
        if metrics else 0.0
    )
    avg_priority = (
        sum(float(item.get("avg_priority_score", 0) or 0) for item in metrics) / len(metrics)
        if metrics else 0.0
    )
    avg_confidence = (
        sum(float(item.get("avg_confidence_pct", 0) or 0) for item in metrics) / len(metrics)
        if metrics else 0.0
    )
    return {
        "suite": report.get("suite"),
        "pass_rate": float(report.get("pass_rate", 0.0) or 0.0),
        "passed_cases": int(report.get("passed_cases", 0) or 0),
        "failed_cases": int(report.get("failed_cases", 0) or 0),
        "missing_cases": int(report.get("missing_cases", 0) or 0),
        "avg_abnormal_priority_score": round(avg_abnormal_priority, 2),
        "avg_priority_score": round(avg_priority, 2),
        "avg_confidence_pct": round(avg_confidence, 2),
        "raw_report": report,
    }


def compare_candidate_to_current(
    current_summary: dict[str, Any],
    candidate_summary: dict[str, Any],
) -> tuple[bool, list[str]]:
    reasons: list[str] = []

    min_candidate_pass_rate = float(cfg("learning.feedback_min_candidate_pass_rate", 1.0))
    max_pass_rate_drop = float(cfg("learning.feedback_max_pass_rate_drop", 0.0))
    max_failed_increase = int(cfg("learning.feedback_max_failed_case_increase", 0))
    max_avg_abnormal_priority_drop = float(cfg("learning.feedback_max_avg_abnormal_priority_drop", 3.0))

    if candidate_summary["pass_rate"] < min_candidate_pass_rate:
        reasons.append(
            f"candidate pass_rate {candidate_summary['pass_rate']:.4f} < {min_candidate_pass_rate:.4f}"
        )

    pass_rate_delta = candidate_summary["pass_rate"] - current_summary["pass_rate"]
    if pass_rate_delta < (-1.0 * max_pass_rate_drop):
        reasons.append(
            f"candidate pass_rate dropped by {abs(pass_rate_delta):.4f} > {max_pass_rate_drop:.4f}"
        )

    failed_delta = candidate_summary["failed_cases"] - current_summary["failed_cases"]
    if failed_delta > max_failed_increase:
        reasons.append(
            f"candidate failed_cases increased by {failed_delta} > {max_failed_increase}"
        )

    abnormal_priority_delta = (
        candidate_summary["avg_abnormal_priority_score"] - current_summary["avg_abnormal_priority_score"]
    )
    if abnormal_priority_delta < (-1.0 * max_avg_abnormal_priority_drop):
        reasons.append(
            "candidate avg_abnormal_priority_score dropped by "
            f"{abs(abnormal_priority_delta):.2f} > {max_avg_abnormal_priority_drop:.2f}"
        )

    return (not reasons), reasons


def promote_candidate_artifacts(
    *,
    ranking_candidate_path: str | Path | None = None,
    calibration_candidate_path: str | Path | None = None,
) -> dict[str, Any]:
    promoted: dict[str, str] = {}
    ranking_target = ranking_model_path()
    calibration_target = calibration_model_path()

    if ranking_candidate_path is not None and Path(ranking_candidate_path).exists():
        ranking_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ranking_candidate_path, ranking_target)
        promoted["ranking"] = str(ranking_target)

    if calibration_candidate_path is not None and Path(calibration_candidate_path).exists():
        calibration_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(calibration_candidate_path, calibration_target)
        promoted["calibration"] = str(calibration_target)

    clear_ranker_cache()
    clear_calibrator_cache()
    return promoted
