"""Confidence calibration helpers for RCA confidence outputs."""

from __future__ import annotations

import argparse
import bisect
import json
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from src.config import cfg_path
from src.eval.benchmark_runner import load_expected_results, resolve_case_pcap
from src.pipeline import process_pcap

try:
    from sklearn.isotonic import IsotonicRegression
except Exception:  # pragma: no cover - dependency may be optional in some envs
    IsotonicRegression = None


_CALIBRATION_CACHE: dict[str, Any] = {"path": None, "payload": None}


def calibration_model_path() -> Path:
    configured = (
        cfg_path("model.confidence_calibration_path")
        or cfg_path("model.calibration_path")
        or "data/models/confidence_calibrator.pkl"
    )
    return Path(configured)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def confidence_band(confidence_pct: float) -> str:
    if confidence_pct >= 85:
        return "high"
    if confidence_pct >= 60:
        return "medium"
    if confidence_pct >= 35:
        return "guarded"
    return "low"


@dataclass
class ConfidenceCalibrator:
    """Small wrapper around isotonic calibration for RCA confidence."""

    _model: object | None = None

    def fit(self, scores: Iterable[float], labels: Iterable[int]) -> "ConfidenceCalibrator":
        if IsotonicRegression is None:
            raise RuntimeError("scikit-learn is required for confidence calibration")
        self._model = IsotonicRegression(out_of_bounds="clip")
        self._model.fit(list(scores), list(labels))
        return self

    def predict(self, scores: Iterable[float]) -> list[float]:
        if self._model is None:
            return [float(score) for score in scores]
        return [float(value) for value in self._model.predict(list(scores))]

    def calibrate(self, score: float) -> float:
        return self.predict([score])[0]


def clear_calibrator_cache() -> None:
    _CALIBRATION_CACHE["path"] = None
    _CALIBRATION_CACHE["payload"] = None


def load_calibrator(model_path: str | Path | None = None) -> dict[str, Any] | None:
    target = Path(model_path or calibration_model_path())
    if not target.exists():
        return None

    cache_key = str(target.resolve())
    if _CALIBRATION_CACHE["path"] == cache_key:
        return _CALIBRATION_CACHE["payload"]

    payload = pickle.loads(target.read_bytes())
    if not isinstance(payload, dict) or "thresholds_x" not in payload or "thresholds_y" not in payload:
        return None

    _CALIBRATION_CACHE["path"] = cache_key
    _CALIBRATION_CACHE["payload"] = payload
    return payload


def build_confidence_training_rows(sessions: list[dict[str, Any]]) -> tuple[list[float], list[int]]:
    scores: list[float] = []
    labels: list[int] = []
    for session in sessions:
        hybrid = session.get("hybrid_rca") or session.get("rca") or {}
        raw_confidence = _safe_float(
            session.get("raw_confidence_pct", hybrid.get("raw_confidence_pct", hybrid.get("confidence_pct", 0))),
            0.0,
        )
        label = session.get("confidence_label")
        if label is None:
            continue
        scores.append(max(0.0, min(1.0, raw_confidence / 100.0)))
        labels.append(1 if bool(label) else 0)
    return scores, labels


def train_confidence_calibrator(
    sessions: list[dict[str, Any]],
    *,
    model_path: str | Path | None = None,
) -> dict[str, Any]:
    scores, labels = build_confidence_training_rows(sessions)
    used_bootstrap_anchors = False
    if scores and len(set(labels)) < 2:
        used_bootstrap_anchors = True
        scores = [0.12, *scores, 0.96]
        labels = [0, *labels, 1]

    if len(scores) < 3 or len(set(labels)) < 2:
        return {
            "trained": False,
            "reason": "insufficient_label_diversity",
            "row_count": len(scores),
        }

    calibrator = ConfidenceCalibrator().fit(scores, labels)
    target = Path(model_path) if model_path is not None else calibration_model_path()
    model = calibrator._model
    payload = {
        "thresholds_x": [float(value) for value in getattr(model, "X_thresholds_", [])],
        "thresholds_y": [float(value) for value in getattr(model, "y_thresholds_", [])],
        "row_count": len(scores),
        "positive_rate": round(sum(labels) / len(labels), 4) if labels else 0.0,
        "model_type": "isotonic",
        "used_bootstrap_anchors": used_bootstrap_anchors,
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(pickle.dumps(payload))
    clear_calibrator_cache()

    return {
        "trained": True,
        "row_count": len(scores),
        "positive_rate": payload["positive_rate"],
        "model_type": "isotonic",
        "used_bootstrap_anchors": used_bootstrap_anchors,
        "model_path": str(target),
    }


def apply_confidence_calibration(
    hybrid_rca: dict[str, Any],
    *,
    model_path: str | Path | None = None,
    use_model: bool = True,
) -> dict[str, Any]:
    result = dict(hybrid_rca or {})
    raw_pct = _safe_float(result.get("raw_confidence_pct", result.get("confidence_pct", 0)), 0.0)
    raw_score = max(0.0, min(1.0, _safe_float(result.get("raw_confidence_score", raw_pct / 100.0), raw_pct / 100.0)))

    calibrated_pct = raw_pct
    calibrated_score = raw_score
    source = "uncalibrated"

    if use_model:
        payload = load_calibrator(model_path=model_path)
        if payload:
            calibrated_score = _interpolate_thresholds(
                raw_score,
                payload.get("thresholds_x") or [],
                payload.get("thresholds_y") or [],
            )
            calibrated_score = max(0.0, min(1.0, calibrated_score))
            calibrated_pct = round(calibrated_score * 100.0, 1)
            source = str(payload.get("model_type") or "calibrated")

    result["raw_confidence_pct"] = round(raw_pct, 1)
    result["raw_confidence_score"] = round(raw_score, 4)
    result["confidence_pct"] = int(round(calibrated_pct))
    result["calibrated_confidence_pct"] = int(round(calibrated_pct))
    result["calibrated_confidence_score"] = round(calibrated_score, 4)
    result["confidence_band"] = confidence_band(calibrated_pct)
    result["calibration_source"] = source

    confidence_model = dict(result.get("confidence_model") or {})
    confidence_model.setdefault("final_label", result.get("rca_label", "UNKNOWN"))
    confidence_model["raw_confidence_score"] = round(raw_score, 4)
    confidence_model["raw_confidence_pct"] = int(round(raw_pct))
    confidence_model["calibrated_confidence_score"] = round(calibrated_score, 4)
    confidence_model["calibrated_confidence_pct"] = int(round(calibrated_pct))
    confidence_model["confidence_score"] = round(calibrated_score, 4)
    confidence_model["confidence_pct"] = int(round(calibrated_pct))
    confidence_model["confidence_band"] = result["confidence_band"]
    confidence_model["calibration_source"] = source
    result["confidence_model"] = confidence_model
    return result


def _interpolate_thresholds(score: float, xs: list[float], ys: list[float]) -> float:
    if not xs or not ys or len(xs) != len(ys):
        return score
    if score <= xs[0]:
        return ys[0]
    if score >= xs[-1]:
        return ys[-1]

    idx = bisect.bisect_left(xs, score)
    if idx <= 0:
        return ys[0]
    if xs[idx] == score:
        return ys[idx]

    left_x = xs[idx - 1]
    right_x = xs[idx]
    left_y = ys[idx - 1]
    right_y = ys[idx]
    if right_x == left_x:
        return right_y
    ratio = (score - left_x) / (right_x - left_x)
    return left_y + ((right_y - left_y) * ratio)


def load_training_sessions(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Training session file must contain a list of sessions")
    return payload


def collect_benchmark_calibration_sessions(suite_path: str | Path) -> list[dict[str, Any]]:
    suite_target = Path(suite_path)
    suite = load_expected_results(suite_target)
    configured_root = Path(suite.get("root_dir") or suite_target.parent)
    root = configured_root if configured_root.is_absolute() else (suite_target.parent / configured_root).resolve()

    sessions: list[dict[str, Any]] = []
    for case in suite.get("cases", []):
        if not (case.get("pcap") or case.get("pcap_candidates") or case.get("pcap_name")):
            continue
        pcap_path = resolve_case_pcap(case, suite_target, root)
        if pcap_path is None or not pcap_path.exists():
            continue

        expected_labels = {str(label).upper() for label in (case.get("required_labels") or {}).keys()}
        dominant_label = str(case.get("dominant_label") or "").upper()
        if dominant_label:
            expected_labels.add(dominant_label)

        case_sessions = process_pcap(str(pcap_path))
        for session in case_sessions:
            hybrid = session.get("hybrid_rca") or session.get("rca") or {}
            label = str(hybrid.get("rca_label", "UNKNOWN")).upper()
            if expected_labels:
                if label in expected_labels:
                    session["confidence_label"] = 1
                elif label == "UNKNOWN" and case.get("max_unknown") == 0:
                    session["confidence_label"] = 0
                else:
                    continue
            else:
                session["confidence_label"] = 0 if label == "UNKNOWN" else 1
            sessions.append(session)
    return sessions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train TraceMAP confidence calibrator")
    parser.add_argument("--sessions", default=None, help="Path to JSON list of session snapshots")
    parser.add_argument("--benchmark-suite", default=None, help="Path to benchmark expected_results.json")
    args = parser.parse_args(argv)

    sessions: list[dict[str, Any]] = []
    if args.sessions:
        sessions.extend(load_training_sessions(args.sessions))
    if args.benchmark_suite:
        sessions.extend(collect_benchmark_calibration_sessions(args.benchmark_suite))

    if not sessions:
        raise SystemExit("No calibration sessions provided")

    result = train_confidence_calibrator(sessions)
    print(json.dumps(result, indent=2))
    return 0 if result.get("trained") else 1


if __name__ == "__main__":
    raise SystemExit(main())
