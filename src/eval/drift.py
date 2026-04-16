"""Simple, explainable drift detection against the golden benchmark baseline."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from src.config import cfg
from src.eval.benchmark_runner import load_expected_results, resolve_case_pcap
from src.pipeline import process_pcap


def _session_label(session: dict[str, Any]) -> str:
    return str(
        (session.get("hybrid_rca") or {}).get("rca_label")
        or (session.get("rca") or {}).get("rca_label")
        or session.get("rca_label")
        or "UNKNOWN"
    ).upper()


def _count_distribution(values: Iterable[str]) -> dict[str, float]:
    counts = Counter(str(value).upper() for value in values if value)
    total = sum(counts.values())
    if total <= 0:
        return {}
    return {key: round(count / total, 4) for key, count in counts.items()}


def _total_variation_distance(left: dict[str, float], right: dict[str, float]) -> float:
    keys = set(left) | set(right)
    return round(sum(abs(float(left.get(key, 0.0)) - float(right.get(key, 0.0))) for key in keys) / 2.0, 4)


def build_session_profile(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [_session_label(session) for session in sessions]
    protocols: list[str] = []
    technologies: list[str] = []
    durations: list[float] = []

    for session in sessions:
        protocols.extend(str(item).upper() for item in (session.get("protocols") or []))
        technologies.extend(str(item).upper() for item in (session.get("technologies") or []))
        try:
            durations.append(float(session.get("duration_ms", 0) or 0))
        except (TypeError, ValueError):
            continue

    return {
        "sample_count": len(sessions),
        "label_distribution": _count_distribution(labels),
        "protocol_distribution": _count_distribution(protocols),
        "technology_distribution": _count_distribution(technologies),
        "avg_duration_ms": round((sum(durations) / len(durations)) if durations else 0.0, 2),
    }


def collect_benchmark_reference_profile(suite_path: str | Path | None = None) -> dict[str, Any]:
    suite_target = Path(suite_path or cfg("autonomous.benchmark_suite", "benchmarks/expected_results.json"))
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
        sessions.extend(process_pcap(str(pcap_path)))
    profile = build_session_profile(sessions)
    profile["suite"] = str(suite_target)
    return profile


def evaluate_feedback_drift(
    feedback_sessions: list[dict[str, Any]],
    *,
    baseline_profile: dict[str, Any] | None = None,
    suite_path: str | Path | None = None,
) -> dict[str, Any]:
    baseline = baseline_profile or collect_benchmark_reference_profile(suite_path=suite_path)
    candidate = build_session_profile(feedback_sessions)

    label_drift = _total_variation_distance(
        candidate.get("label_distribution") or {},
        baseline.get("label_distribution") or {},
    )
    protocol_drift = _total_variation_distance(
        candidate.get("protocol_distribution") or {},
        baseline.get("protocol_distribution") or {},
    )
    technology_drift = _total_variation_distance(
        candidate.get("technology_distribution") or {},
        baseline.get("technology_distribution") or {},
    )

    baseline_avg_duration = float(baseline.get("avg_duration_ms") or 0.0)
    candidate_avg_duration = float(candidate.get("avg_duration_ms") or 0.0)
    if baseline_avg_duration <= 0.0:
        duration_ratio_delta = 0.0 if candidate_avg_duration <= 0.0 else 999.0
    else:
        duration_ratio_delta = abs(candidate_avg_duration - baseline_avg_duration) / baseline_avg_duration

    checks = [
        {
            "name": "label_drift_within_limit",
            "passed": label_drift <= float(cfg("learning.feedback_max_label_drift", 0.55)),
            "detail": f"label_drift={label_drift:.4f}",
        },
        {
            "name": "protocol_drift_within_limit",
            "passed": protocol_drift <= float(cfg("learning.feedback_max_protocol_drift", 0.6)),
            "detail": f"protocol_drift={protocol_drift:.4f}",
        },
        {
            "name": "technology_drift_within_limit",
            "passed": technology_drift <= float(cfg("learning.feedback_max_technology_drift", 0.6)),
            "detail": f"technology_drift={technology_drift:.4f}",
        },
        {
            "name": "avg_duration_delta_within_limit",
            "passed": duration_ratio_delta <= float(cfg("learning.feedback_max_avg_duration_ratio_delta", 2.5)),
            "detail": f"avg_duration_ratio_delta={duration_ratio_delta:.4f}",
        },
    ]

    return {
        "passed": all(check["passed"] for check in checks),
        "baseline": baseline,
        "candidate": candidate,
        "label_drift": label_drift,
        "protocol_drift": protocol_drift,
        "technology_drift": technology_drift,
        "avg_duration_ratio_delta": round(duration_ratio_delta, 4),
        "checks": checks,
    }
