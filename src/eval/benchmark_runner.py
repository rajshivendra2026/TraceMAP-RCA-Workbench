"""Benchmark suite runner for TraceMAP reliability gating."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from src.config import cfg_path
from src.pipeline import process_pcap

from .metrics import benchmark_case_passed, compute_case_metrics


def benchmark_root_dir() -> Path:
    return Path(cfg_path("benchmarks.dir", "benchmarks"))


def expected_results_path() -> Path:
    return benchmark_root_dir() / "expected_results.json"


def load_expected_results(path: str | Path | None = None) -> dict[str, Any]:
    target = Path(path or expected_results_path())
    if not target.exists():
        return {"cases": []}
    payload = json.loads(target.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return {"cases": payload}
    if isinstance(payload, dict):
        payload.setdefault("cases", [])
        return payload
    return {"cases": []}


def run_benchmark_suite(
    *,
    suite_path: str | Path | None = None,
    process_fn: Callable[[str], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    suite_target = Path(suite_path or expected_results_path())
    suite = load_expected_results(suite_target)
    configured_root = Path(suite.get("root_dir") or benchmark_root_dir())
    root = configured_root if configured_root.is_absolute() else (suite_target.parent / configured_root).resolve()
    runner = process_fn or process_pcap
    results: list[dict[str, Any]] = []

    for case in suite.get("cases", []):
        rel_path = case.get("pcap")
        if not rel_path:
            continue
        pcap_path = root / rel_path
        case_result = {
            "name": case.get("name") or Path(rel_path).name,
            "pcap": str(pcap_path),
            "status": "pending",
        }
        if not pcap_path.exists():
            case_result["status"] = "missing"
            results.append(case_result)
            continue

        sessions = runner(str(pcap_path))
        metrics = compute_case_metrics(sessions, case)
        passed, reasons = benchmark_case_passed(metrics, case)
        case_result.update(
            {
                "status": "passed" if passed else "failed",
                "metrics": metrics,
                "reasons": reasons,
            }
        )
        results.append(case_result)

    passed_count = len([item for item in results if item["status"] == "passed"])
    failed_count = len([item for item in results if item["status"] == "failed"])
    missing_count = len([item for item in results if item["status"] == "missing"])
    runnable_count = passed_count + failed_count
    pass_rate = (passed_count / runnable_count) if runnable_count else 0.0

    return {
        "suite": str(Path(suite_path or expected_results_path())),
        "root_dir": str(root),
        "total_cases": len(results),
        "passed_cases": passed_count,
        "failed_cases": failed_count,
        "missing_cases": missing_count,
        "pass_rate": round(pass_rate, 4),
        "cases": results,
    }
