"""Autonomous watcher for gated seed refresh and git publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger

from src.app.learning import default_learning_path, discover_pcaps
from src.config import cfg, cfg_path, project_root
from src.eval.benchmark_runner import run_benchmark_suite
from src.pipeline import process_pcap


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def knowledge_base_dir() -> Path:
    return Path(cfg_path("data.knowledge_base", "data/knowledge_base"))


def report_dir() -> Path:
    return Path(
        cfg_path(
            "autonomous.run_reports_dir",
            str(knowledge_base_dir() / "run_reports"),
        )
    )


def curated_seed_files() -> list[str]:
    configured = cfg(
        "autonomous.curated_seed_files",
        [
            "knowledge_graph.json",
            "metrics.json",
            "patterns.json",
            "timeseries_intelligence.json",
            "vectors.json",
        ],
    )
    return [str(item) for item in configured]


def snapshot_seed_state(base_dir: Path | None = None, include_validation: bool = False) -> dict[str, Any]:
    base = Path(base_dir or knowledge_base_dir())
    files: dict[str, dict[str, Any]] = {}
    pattern_count = 0
    pending_validation = 0
    metrics = _safe_json(base / "metrics.json", {})

    for name in curated_seed_files():
        path = base / name
        if not path.exists():
            continue
        files[name] = _file_state(path)
        if name == "patterns.json":
            pattern_count = len(_safe_json(path, []))

    validation_queue = _safe_json(base / "validation_queue.json", [])
    pending_validation = len(
        [item for item in validation_queue if item.get("validation_status", "pending_review") == "pending_review"]
    )
    if include_validation:
        path = base / "validation_queue.json"
        if path.exists():
            files["validation_queue.json"] = _file_state(path)

    return {
        "base_dir": str(base),
        "files": files,
        "metrics": metrics,
        "pattern_count": pattern_count,
        "pending_validation": pending_validation,
    }


class SeedRefreshPolicy:
    """Apply quality gates before promoting learned knowledge to git."""

    def __init__(
        self,
        max_unknown_ratio: float | None = None,
        max_validation_queue_growth: int | None = None,
        max_pattern_drop: int | None = None,
        benchmark_enabled: bool | None = None,
        min_benchmark_pass_rate: float | None = None,
    ):
        self.max_unknown_ratio = float(cfg("autonomous.max_unknown_ratio", 0.35)) if max_unknown_ratio is None else float(max_unknown_ratio)
        self.max_validation_queue_growth = int(cfg("autonomous.max_validation_queue_growth", 25)) if max_validation_queue_growth is None else int(max_validation_queue_growth)
        self.max_pattern_drop = int(cfg("autonomous.max_pattern_drop", 0)) if max_pattern_drop is None else int(max_pattern_drop)
        self.benchmark_enabled = bool(cfg("autonomous.benchmark_enabled", False)) if benchmark_enabled is None else bool(benchmark_enabled)
        self.min_benchmark_pass_rate = float(cfg("autonomous.min_benchmark_pass_rate", 1.0)) if min_benchmark_pass_rate is None else float(min_benchmark_pass_rate)

    def evaluate(
        self,
        before: dict[str, Any],
        after: dict[str, Any],
        cycle: dict[str, Any],
    ) -> dict[str, Any]:
        changed_files = sorted(
            name
            for name in after.get("files", {})
            if before.get("files", {}).get(name, {}).get("sha1") != after["files"][name].get("sha1")
        )
        processed_sessions = int(cycle.get("session_count", 0))
        unknown_sessions = int(cycle.get("label_counts", {}).get("UNKNOWN", 0))
        unknown_ratio = (unknown_sessions / processed_sessions) if processed_sessions else 0.0
        queue_growth = int(after.get("pending_validation", 0)) - int(before.get("pending_validation", 0))
        pattern_delta = int(after.get("pattern_count", 0)) - int(before.get("pattern_count", 0))

        checks = [
            {
                "name": "seed_files_changed",
                "passed": bool(changed_files),
                "detail": "No curated seed files changed." if not changed_files else f"Changed: {', '.join(changed_files)}",
            },
            {
                "name": "unknown_ratio_within_limit",
                "passed": unknown_ratio <= self.max_unknown_ratio,
                "detail": f"UNKNOWN ratio {unknown_ratio:.3f} exceeds limit {self.max_unknown_ratio:.3f}."
                if unknown_ratio > self.max_unknown_ratio
                else f"UNKNOWN ratio {unknown_ratio:.3f} within limit.",
            },
            {
                "name": "validation_queue_growth_within_limit",
                "passed": queue_growth <= self.max_validation_queue_growth,
                "detail": f"Pending validation grew by {queue_growth}, limit is {self.max_validation_queue_growth}."
                if queue_growth > self.max_validation_queue_growth
                else f"Pending validation delta {queue_growth}.",
            },
            {
                "name": "pattern_drop_within_limit",
                "passed": pattern_delta >= (-1 * self.max_pattern_drop),
                "detail": f"Pattern count fell by {-pattern_delta}, limit is {self.max_pattern_drop}."
                if pattern_delta < (-1 * self.max_pattern_drop)
                else f"Pattern delta {pattern_delta}.",
            },
        ]
        benchmark_report = cycle.get("benchmark") or {}
        if self.benchmark_enabled:
            pass_rate = float(benchmark_report.get("pass_rate", 0.0) or 0.0)
            missing_cases = int(benchmark_report.get("missing_cases", 0) or 0)
            benchmark_passed = (
                benchmark_report.get("executed") is True
                and missing_cases == 0
                and pass_rate >= self.min_benchmark_pass_rate
            )
            detail = (
                f"Benchmark pass rate {pass_rate:.3f}, missing cases {missing_cases}."
                if benchmark_report.get("executed")
                else str(benchmark_report.get("reason") or "Benchmark suite was not executed.")
            )
            if benchmark_report.get("error"):
                detail = f"{detail} Error: {benchmark_report['error']}"
            checks.append(
                {
                    "name": "benchmark_suite_passed",
                    "passed": benchmark_passed,
                    "detail": detail,
                }
            )
        passed = all(check["passed"] for check in checks)
        return {
            "passed": passed,
            "checks": checks,
            "changed_files": changed_files,
            "unknown_ratio": round(unknown_ratio, 4),
            "validation_queue_growth": queue_growth,
            "pattern_delta": pattern_delta,
        }


class GitPublisher:
    """Commit and optionally push curated seed updates."""

    def __init__(self, repo_root: str | Path | None = None):
        self.repo_root = Path(repo_root or project_root())

    def publish(
        self,
        paths: list[str],
        message: str,
        push: bool = False,
        branch: str | None = None,
    ) -> dict[str, Any]:
        unique_paths = [str(path) for path in dict.fromkeys(paths) if path]
        if not unique_paths:
            return {"committed": False, "pushed": False, "reason": "no_paths"}

        changed = self._changed_paths(unique_paths)
        if not changed:
            return {"committed": False, "pushed": False, "reason": "no_changes"}

        rel_changed = [self._to_repo_relative(path) for path in changed]
        self._run(["git", "add", "--", *rel_changed])
        commit_result = self._run(["git", "commit", "-m", message], check=False)
        if commit_result.returncode != 0:
            return {
                "committed": False,
                "pushed": False,
                "reason": "commit_failed",
                "stdout": commit_result.stdout,
                "stderr": commit_result.stderr,
            }

        pushed = False
        push_error = None
        push_branch = branch or "main"
        if push:
            push_result = self._run(["git", "push", "origin", f"HEAD:{push_branch}"], check=False)
            pushed = push_result.returncode == 0
            if not pushed:
                push_error = push_result.stderr or push_result.stdout

        return {
            "committed": True,
            "pushed": pushed,
            "branch": push_branch if push else None,
            "paths": rel_changed,
            "commit_message": message,
            "push_error": push_error,
        }

    def _changed_paths(self, paths: list[str]) -> list[str]:
        changed: list[str] = []
        for path in paths:
            repo_path = self._to_repo_relative(path)
            result = self._run(["git", "status", "--short", "--", repo_path], check=False)
            if result.stdout.strip():
                changed.append(path)
        return changed

    def _to_repo_relative(self, path: str) -> str:
        candidate = Path(path)
        try:
            return str(candidate.resolve().relative_to(self.repo_root.resolve()))
        except ValueError:
            return str(candidate)

    def _run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            cwd=self.repo_root,
            check=check,
            capture_output=True,
            text=True,
        )


class AutonomousLearningWatcher:
    """Local watcher that learns from new traces and promotes gated seed updates."""

    def __init__(
        self,
        watch_paths: list[str] | None = None,
        manifest_path: str | Path | None = None,
        base_dir: str | Path | None = None,
        policy: SeedRefreshPolicy | None = None,
        git_publisher: GitPublisher | None = None,
    ):
        configured_paths = cfg("autonomous.watch_paths", [default_learning_path()])
        if isinstance(configured_paths, str):
            configured_paths = [configured_paths]
        self.watch_paths = [str(Path(path).resolve()) for path in (watch_paths or configured_paths)]
        self.base_dir = Path(base_dir or knowledge_base_dir())
        self.manifest_path = Path(manifest_path or (self.base_dir / "processed_sources.json"))
        self.policy = policy or SeedRefreshPolicy()
        self.git_publisher = git_publisher or GitPublisher()

    def discover_pending(self) -> list[dict[str, Any]]:
        manifest = self._load_manifest()
        manifest_updates: dict[str, Any] = {}
        seen = set(manifest)
        pending: list[dict[str, Any]] = []
        for root in self.watch_paths:
            for item in discover_pcaps(root):
                if item["signature"] not in seen:
                    pending.append(item)
        return pending

    def run_cycle(self, pending_files: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        pending = list(pending_files or self.discover_pending())
        cycle_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report_path = str(report_dir() / f"{cycle_id}.json")
        report = {
            "cycle_id": cycle_id,
            "started_at": utc_now(),
            "watch_paths": self.watch_paths,
            "pending_trace_count": len(pending),
            "processed_trace_count": 0,
            "processed_files": [],
            "session_count": 0,
            "label_counts": {},
            "learning_metrics": {},
            "benchmark": {
                "executed": False,
                "pass_rate": 0.0,
                "passed_cases": 0,
                "failed_cases": 0,
                "missing_cases": 0,
            },
            "gate": {"passed": False, "checks": [], "changed_files": []},
            "git": {"committed": False, "pushed": False},
            "manifest_persisted": False,
            "report_path": report_path,
        }
        before = snapshot_seed_state(self.base_dir)

        if not pending:
            report["status"] = "idle"
            report["finished_at"] = utc_now()
            self._write_report(report)
            return report

        manifest = self._load_manifest()
        manifest_updates: dict[str, Any] = {}
        all_sessions: list[dict[str, Any]] = []
        learning_metrics = Counter()

        try:
            for item in pending:
                sessions = process_pcap(item["path"], raise_on_error=True)
                report["processed_files"].append(
                    {
                        "path": item["path"],
                        "name": item["name"],
                        "signature": item["signature"],
                        "session_count": len(sessions),
                        "label_counts": dict(
                            Counter((session.get("rca") or {}).get("rca_label", "UNKNOWN") for session in sessions)
                        ),
                    }
                )
                all_sessions.extend(sessions)
                manifest_updates[item["signature"]] = {
                    "path": item["path"],
                    "name": item["name"],
                    "size": item["size"],
                    "mtime": item["mtime"],
                    "learned_at": time.time(),
                    "autonomous_cycle_id": cycle_id,
                }

                for key, value in ((sessions[0].get("learning_metrics") if sessions else {}) or {}).items():
                    learning_metrics[key] += int(value)

            report["processed_trace_count"] = len(pending)
            report["session_count"] = len(all_sessions)
            report["label_counts"] = dict(
                Counter((session.get("rca") or {}).get("rca_label", "UNKNOWN") for session in all_sessions)
            )
            report["learning_metrics"] = dict(learning_metrics)
            report["benchmark"] = self._run_benchmarks()

            after = snapshot_seed_state(self.base_dir)
            gate = self.policy.evaluate(before, after, report)
            report["gate"] = gate
            report["status"] = "accepted" if gate["passed"] else "held"

            auto_commit = bool(cfg("autonomous.auto_commit", False))
            if gate["passed"] and auto_commit:
                commit_paths = [str(self.base_dir / name) for name in gate["changed_files"]]
                trace_names = ", ".join(item["name"] for item in pending[:3])
                if len(pending) > 3:
                    trace_names += f" +{len(pending) - 3} more"
                commit_message = f"Refresh autonomous seed learning from {trace_names}"
                report["git"] = self.git_publisher.publish(
                    paths=commit_paths,
                    message=commit_message,
                    push=bool(cfg("autonomous.auto_push", False)),
                    branch=str(cfg("autonomous.push_branch", "learning-updates")),
                )
                if not report["git"].get("committed"):
                    report["status"] = "failed"
            else:
                report["git"] = {
                    "committed": False,
                    "pushed": False,
                    "reason": "gates_blocked" if not gate["passed"] else "auto_commit_disabled",
                }

            if report["status"] == "accepted":
                manifest.update(manifest_updates)
                self._save_manifest(manifest)
                report["manifest_persisted"] = True

            report["finished_at"] = utc_now()
            self._write_report(report)
            return report
        except Exception as exc:
            report["status"] = "failed"
            report["error"] = str(exc)
            report["finished_at"] = utc_now()
            self._write_report(report)
            raise

    def run_forever(self, poll_interval_sec: int | None = None, max_cycles: int | None = None) -> None:
        interval = int(poll_interval_sec or cfg("autonomous.poll_interval_sec", 60))
        cycles = 0
        while True:
            report = self.run_cycle()
            logger.info(
                "Autonomous watcher cycle {} finished with status={} processed={}",
                report["cycle_id"],
                report.get("status"),
                report.get("processed_trace_count"),
            )
            cycles += 1
            if max_cycles is not None and cycles >= max_cycles:
                return
            time.sleep(interval)

    def _load_manifest(self) -> dict[str, Any]:
        if not self.manifest_path.exists():
            return {}
        try:
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_manifest(self, payload: dict[str, Any]) -> None:
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _write_report(self, report: dict[str, Any]) -> str:
        directory = report_dir()
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{report['cycle_id']}.json"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return str(path)

    def _run_benchmarks(self) -> dict[str, Any]:
        if not cfg("autonomous.benchmark_enabled", False):
            return {
                "executed": False,
                "reason": "benchmark_disabled",
                "pass_rate": 0.0,
                "passed_cases": 0,
                "failed_cases": 0,
                "missing_cases": 0,
            }
        suite_path = cfg("autonomous.benchmark_suite", "benchmarks/expected_results.json")
        try:
            report = run_benchmark_suite(suite_path=suite_path)
            report["executed"] = True
            return report
        except Exception as exc:  # pragma: no cover - defensive runtime path
            logger.exception("Benchmark suite execution failed: {}", exc)
            return {
                "executed": False,
                "reason": "benchmark_error",
                "error": str(exc),
                "pass_rate": 0.0,
                "passed_cases": 0,
                "failed_cases": 0,
                "missing_cases": 0,
            }


def _safe_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _file_state(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {
        "size": len(raw),
        "sha1": hashlib.sha1(raw).hexdigest(),
        "mtime": int(path.stat().st_mtime),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Autonomous telecom seed-learning watcher")
    parser.add_argument("--once", action="store_true", help="Run one learning cycle and exit.")
    parser.add_argument("--interval", type=int, default=None, help="Polling interval in seconds.")
    parser.add_argument("--max-cycles", type=int, default=None, help="Optional stop after N cycles.")
    args = parser.parse_args(argv)

    watcher = AutonomousLearningWatcher()
    if args.once:
        report = watcher.run_cycle()
        logger.info("Autonomous watcher report written to {}", report.get("report_path"))
        return 0
    watcher.run_forever(poll_interval_sec=args.interval, max_cycles=args.max_cycles)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
