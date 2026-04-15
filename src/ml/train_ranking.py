"""Training helpers for the learned analyst-priority ranker."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from src.eval.benchmark_runner import load_expected_results, resolve_case_pcap
from src.features.feature_engineer import extract_features, extract_trace_intelligence
from src.pipeline import process_pcap

from .ranking import (
    build_priority_feature_row,
    clear_ranker_cache,
    feature_names,
    heuristic_priority_score,
    ranking_model_path,
)

try:
    import joblib
except Exception:  # pragma: no cover - optional dependency in some envs
    joblib = None

try:
    import lightgbm as lgb
except Exception:  # pragma: no cover - dependency may be absent in local envs
    lgb = None

try:
    from sklearn.ensemble import HistGradientBoostingRegressor
except Exception:  # pragma: no cover - dependency may be absent in some envs
    HistGradientBoostingRegressor = None


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def build_training_rows(sessions: list[dict[str, Any]]) -> tuple[list[dict[str, float]], list[float]]:
    rows: list[dict[str, float]] = []
    labels: list[float] = []
    for session in sessions:
        features = session.get("features") or extract_features(session)
        intelligence = session.get("trace_intelligence") or extract_trace_intelligence(session)
        hybrid = session.get("hybrid_rca") or session.get("rca") or {}
        anomaly = (hybrid.get("anomaly") or session.get("anomaly") or {})
        pattern_match = hybrid.get("pattern_match") or {}
        confidence_model = hybrid.get("confidence_model") or {}
        heuristic = heuristic_priority_score(
            session,
            features=features,
            intelligence=intelligence,
            hybrid_rca=hybrid,
            anomaly_result=anomaly,
            pattern_match=pattern_match,
            confidence_model=confidence_model,
        )
        rows.append(
            build_priority_feature_row(
                session,
                features=features,
                intelligence=intelligence,
                hybrid_rca=hybrid,
                anomaly_result=anomaly,
                pattern_match=pattern_match,
                confidence_model=confidence_model,
                heuristic=heuristic,
            )
        )
        labels.append(_safe_float(session.get("priority_label", heuristic["priority_score"])))
    return rows, labels


def _fit_model(matrix: list[list[float]], labels: list[float]) -> tuple[object | None, str | None]:
    if lgb is not None:
        dataset = lgb.Dataset(matrix, label=labels, feature_name=feature_names())
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
        return model, "lightgbm"

    if HistGradientBoostingRegressor is not None:
        model = HistGradientBoostingRegressor(
            learning_rate=0.05,
            max_depth=6,
            max_iter=120,
            random_state=42,
        )
        model.fit(matrix, labels)
        return model, "hist_gradient_boosting"

    return None, None


def train_ranking_model(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    rows, labels = build_training_rows(sessions)
    names = feature_names()
    matrix = [[row.get(name, 0.0) for name in names] for row in rows]
    model, model_type = _fit_model(matrix, labels)
    if model is None:
        return {
            "trained": False,
            "reason": "supported_regressor_not_available",
            "row_count": len(rows),
        }

    target = ranking_model_path()
    metadata = {
        "model": model,
        "features": names,
        "model_type": model_type,
        "row_count": len(rows),
    }
    if joblib is not None:
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(metadata, target)
        clear_ranker_cache()

    return {
        "trained": True,
        "row_count": len(rows),
        "feature_names": names,
        "model_type": model_type,
        "model_path": str(target) if joblib is not None else None,
    }


def load_training_sessions(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Training session file must contain a list of sessions")
    return payload


def collect_benchmark_sessions(suite_path: str | Path) -> list[dict[str, Any]]:
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
        case_sessions = process_pcap(str(pcap_path))
        expected_dominant = str(case.get("dominant_label") or "").upper()
        max_unknown = case.get("max_unknown")
        for session in case_sessions:
            label = str(
                (session.get("hybrid_rca") or session.get("rca") or {}).get("rca_label")
                or "UNKNOWN"
            ).upper()
            heuristic_score = _safe_float(session.get("priority_score", 0))
            target_score = heuristic_score
            if expected_dominant and label == expected_dominant and label != "NORMAL_CALL":
                target_score = max(target_score, 80.0)
            elif expected_dominant and label == expected_dominant:
                target_score = max(target_score, 35.0)
            if label == "UNKNOWN" and max_unknown == 0:
                target_score = max(target_score, 82.0)
            session["priority_label"] = min(99.0, target_score)
        sessions.extend(case_sessions)
    return sessions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train TraceMAP learned session-priority ranker")
    parser.add_argument("--sessions", default=None, help="Path to JSON list of session snapshots")
    parser.add_argument("--benchmark-suite", default=None, help="Path to benchmark expected_results.json")
    args = parser.parse_args(argv)

    sessions: list[dict[str, Any]] = []
    if args.sessions:
        sessions.extend(load_training_sessions(args.sessions))
    if args.benchmark_suite:
        sessions.extend(collect_benchmark_sessions(args.benchmark_suite))

    if not sessions:
        raise SystemExit("No training sessions provided")

    result = train_ranking_model(sessions)
    print(json.dumps(result, indent=2))
    return 0 if result.get("trained") else 1


if __name__ == "__main__":
    raise SystemExit(main())
