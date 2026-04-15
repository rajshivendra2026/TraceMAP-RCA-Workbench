"""Benchmark suite runner for TraceMAP reliability gating."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable

from src.config import cfg, cfg_path
from src.pipeline import process_pcap

from .metrics import benchmark_case_passed, compute_case_metrics


def benchmark_root_dir() -> Path:
    return Path(cfg_path("benchmarks.dir", "benchmarks"))


def expected_results_path() -> Path:
    return benchmark_root_dir() / "expected_results.json"


def configured_benchmark_roots() -> list[Path]:
    configured = cfg("benchmarks.roots", [])
    if isinstance(configured, str):
        configured = [configured]
    roots: list[Path] = []
    for item in configured:
        path = Path(str(item)).expanduser()
        roots.append(path.resolve() if not path.is_absolute() else path)
    return roots


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


def resolve_case_pcap(case: dict[str, Any], suite_target: Path, root: Path) -> Path | None:
    candidates: list[Path] = []

    direct = case.get("pcap")
    if direct:
        direct_path = Path(str(direct)).expanduser()
        candidates.append(direct_path if direct_path.is_absolute() else (root / direct_path))

    for item in case.get("pcap_candidates") or []:
        candidate = Path(str(item)).expanduser()
        candidates.append(candidate if candidate.is_absolute() else (root / candidate))

    file_name = case.get("pcap_name")
    search_roots = [root, *configured_benchmark_roots()]
    if file_name:
        for search_root in search_roots:
            candidates.append(search_root / str(file_name))
            if search_root.exists():
                candidates.extend(search_root.rglob(str(file_name)))

    seen: set[str] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        if resolved.exists():
            return resolved
    return None


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
        if not (case.get("pcap") or case.get("pcap_candidates") or case.get("pcap_name")):
            continue
        pcap_path = resolve_case_pcap(case, suite_target, root)
        case_result = {
            "name": case.get("name") or Path(str(case.get("pcap") or case.get("pcap_name") or "case")).name,
            "pcap": str(pcap_path) if pcap_path else str(case.get("pcap") or case.get("pcap_name") or ""),
            "status": "pending",
        }
        if pcap_path is None or not pcap_path.exists():
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run TraceMAP golden benchmark suite")
    parser.add_argument("--suite", default=None, help="Path to expected_results.json")
    args = parser.parse_args(argv)
    report = run_benchmark_suite(suite_path=args.suite)
    print(json.dumps(report, indent=2))
    return 0 if report["failed_cases"] == 0 and report["missing_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
