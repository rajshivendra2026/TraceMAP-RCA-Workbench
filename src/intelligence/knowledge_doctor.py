"""Audit and safely repair generated knowledge-base artifacts."""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

from src.autonomous.graph_store import GraphStore
from src.autonomous.knowledge_graph import TelecomKnowledgeGraph
from src.autonomous.timeseries_engine import TimeSeriesIntelligenceEngine
from src.config import cfg_path
from src.intelligence.knowledge_engine import KnowledgeEngine


class KnowledgeBaseDoctor:
    """Inspect generated knowledge artifacts and apply safe self-healing repairs."""

    def __init__(self, base_dir: str | None = None):
        self.base_dir = Path(base_dir or cfg_path("data.knowledge_base", "data/knowledge_base"))
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.patterns_path = self.base_dir / "patterns.json"
        self.vectors_path = self.base_dir / "vectors.json"
        self.metrics_path = self.base_dir / "metrics.json"
        self.validation_path = self.base_dir / "validation_queue.json"
        self.learning_settings_path = self.base_dir / "learning_settings.json"
        self.processed_sources_path = self.base_dir / "processed_sources.json"
        self.knowledge_graph_path = self.base_dir / "knowledge_graph.json"
        self.timeseries_path = self.base_dir / "timeseries_intelligence.json"
        self.run_reports_dir = self.base_dir / "run_reports"

    def audit(self) -> dict[str, Any]:
        return self._audit_state(self._load_state(), repair_requested=False, repair_applied=False, repair_actions=[])

    def enforce(self, repair: bool = False, strict: bool = False) -> dict[str, Any]:
        repair_actions: list[str] = []
        repair_issue: dict[str, Any] | None = None
        initial = self._load_state()
        report = self._audit_state(initial, repair_requested=repair, repair_applied=False, repair_actions=repair_actions)

        if repair and report["repairable_issue_count"] > 0:
            try:
                repair_actions = self._apply_safe_repairs(initial)
            except Exception as exc:  # pragma: no cover - defensive runtime path
                repair_issue = self._issue(
                    severity="error",
                    code="repair_failed",
                    file=str(self.base_dir),
                    message=f"Knowledge-base repair failed: {exc}",
                    repairable=False,
                )
            report = self._audit_state(
                self._load_state(),
                repair_requested=True,
                repair_applied=bool(repair_actions),
                repair_actions=repair_actions,
                extra_issues=[repair_issue] if repair_issue else [],
            )

        if strict and report["error_count"] > 0:
            codes = ", ".join(issue["code"] for issue in report["issues"] if issue["severity"] == "error")
            raise RuntimeError(f"Knowledge base health check failed: {codes}")

        return report

    def _apply_safe_repairs(self, state: dict[str, Any]) -> list[str]:
        actions: list[str] = []
        pattern_dims = state["facts"]["pattern_embedding_dimensions"]
        duplicate_pattern_ids = state["facts"]["duplicate_pattern_ids"]
        if len(pattern_dims) <= 1 and not duplicate_pattern_ids:
            KnowledgeEngine(base_dir=str(self.base_dir)).save()
            actions.append("Reconciled patterns, vectors, metrics, and pending validation queue.")

        graph = state.get("knowledge_graph")
        if isinstance(graph.get("nodes"), dict) and isinstance(graph.get("edges"), dict):
            knowledge_graph = TelecomKnowledgeGraph(store=GraphStore(base_dir=str(self.base_dir)))
            knowledge_graph.rebuild_metrics()
            knowledge_graph.save()
            actions.append("Rebuilt knowledge graph metrics from stored nodes and edges.")

        timeseries = state.get("timeseries")
        if isinstance(timeseries.get("events"), list):
            engine = TimeSeriesIntelligenceEngine(base_dir=str(self.base_dir))
            engine.state["recurring_summary"] = engine.detect_recurring_failures()
            timestamps = [str(event.get("timestamp")) for event in engine.state.get("events", []) if event.get("timestamp")]
            engine.state["last_updated"] = max(timestamps) if timestamps else None
            engine._save()
            actions.append("Recomputed time-series recurring summary from recorded events.")

        settings = state.get("learning_settings")
        saved_path = settings.get("learn_path") if isinstance(settings, dict) else None
        if saved_path and not Path(saved_path).expanduser().exists():
            fallback = str(Path(cfg_path("data.raw_pcaps", "data/raw_pcaps")).expanduser().resolve())
            payload = dict(settings)
            payload["learn_path"] = fallback
            payload["updated_at"] = time.time()
            self._write_json(self.learning_settings_path, payload)
            actions.append("Reset stale learning path to the configured raw-PCAP directory.")

        return actions

    def _audit_state(
        self,
        state: dict[str, Any],
        *,
        repair_requested: bool,
        repair_applied: bool,
        repair_actions: list[str],
        extra_issues: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        patterns = state["patterns"]
        vectors = state["vectors"]
        metrics = state["metrics"]
        validation_queue = state["validation_queue"]
        learning_settings = state["learning_settings"]
        processed_sources = state["processed_sources"]
        knowledge_graph = state["knowledge_graph"]
        timeseries = state["timeseries"]
        facts = state["facts"]

        if len(facts["duplicate_pattern_ids"]) > 0:
            issues.append(
                self._issue(
                    severity="error",
                    code="duplicate_pattern_ids",
                    file=str(self.patterns_path),
                    message=f"Found duplicate pattern ids: {', '.join(sorted(facts['duplicate_pattern_ids']))}.",
                    repairable=False,
                )
            )
        if facts["invalid_patterns_shape"]:
            issues.append(
                self._issue(
                    severity="error",
                    code="invalid_patterns_shape",
                    file=str(self.patterns_path),
                    message="patterns.json must store a list of pattern objects.",
                    repairable=False,
                )
            )
        if facts["invalid_vectors_shape"]:
            issues.append(
                self._issue(
                    severity="error",
                    code="invalid_vectors_shape",
                    file=str(self.vectors_path),
                    message="vectors.json must store a list of vector records.",
                    repairable=True,
                )
            )
        if facts["invalid_metrics_shape"]:
            issues.append(
                self._issue(
                    severity="error",
                    code="invalid_metrics_shape",
                    file=str(self.metrics_path),
                    message="metrics.json must store a dictionary of derived counters.",
                    repairable=True,
                )
            )
        if facts["invalid_validation_shape"]:
            issues.append(
                self._issue(
                    severity="error",
                    code="invalid_validation_shape",
                    file=str(self.validation_path),
                    message="validation_queue.json must store a list of validation records.",
                    repairable=True,
                )
            )
        if facts["invalid_processed_sources_shape"]:
            issues.append(
                self._issue(
                    severity="error",
                    code="invalid_processed_sources_shape",
                    file=str(self.processed_sources_path),
                    message="processed_sources.json must store a dictionary keyed by trace signature.",
                    repairable=False,
                )
            )

        if len(facts["pattern_embedding_dimensions"]) > 1:
            issues.append(
                self._issue(
                    severity="error",
                    code="pattern_embedding_dimension_mismatch",
                    file=str(self.patterns_path),
                    message=(
                        "Pattern embeddings use multiple dimensions: "
                        f"{sorted(facts['pattern_embedding_dimensions'])}."
                    ),
                    repairable=False,
                )
            )
        if facts["orphan_vector_ids"]:
            issues.append(
                self._issue(
                    severity="error",
                    code="orphan_vectors",
                    file=str(self.vectors_path),
                    message=f"Found {len(facts['orphan_vector_ids'])} vector ids with no matching pattern.",
                    repairable=True,
                )
            )
        if facts["missing_vector_ids"]:
            issues.append(
                self._issue(
                    severity="error",
                    code="missing_vectors",
                    file=str(self.vectors_path),
                    message=f"Found {len(facts['missing_vector_ids'])} patterns with embeddings but no vector record.",
                    repairable=True,
                )
            )
        if len(facts["vector_dimensions"]) > 1:
            issues.append(
                self._issue(
                    severity="error",
                    code="vector_dimension_mismatch",
                    file=str(self.vectors_path),
                    message=f"Vector store contains mixed dimensions: {sorted(facts['vector_dimensions'])}.",
                    repairable=True,
                )
            )

        expected_metrics = {
            "pattern_count": len(patterns),
            "candidate_pattern_count": len(vectors),
            "validation_queue_size": facts["pending_validation_count"],
            "validated_count": facts["approved_validation_count"],
            "rejected_count": facts["rejected_validation_count"],
        }
        metric_mismatches = {
            key: {"stored": metrics.get(key), "expected": expected}
            for key, expected in expected_metrics.items()
            if metrics.get(key) != expected
        }
        if metric_mismatches:
            issues.append(
                self._issue(
                    severity="error",
                    code="metrics_out_of_sync",
                    file=str(self.metrics_path),
                    message=f"Derived metrics are out of sync for {', '.join(sorted(metric_mismatches))}.",
                    repairable=True,
                    details=metric_mismatches,
                )
            )

        if facts["duplicate_pending_validation_groups"] > 0:
            issues.append(
                self._issue(
                    severity="error",
                    code="duplicate_pending_validation",
                    file=str(self.validation_path),
                    message=(
                        "Pending validation queue contains "
                        f"{facts['duplicate_pending_validation_groups']} duplicate key groups."
                    ),
                    repairable=True,
                )
            )

        saved_path = learning_settings.get("learn_path") if isinstance(learning_settings, dict) else None
        if saved_path and not Path(saved_path).expanduser().exists():
            issues.append(
                self._issue(
                    severity="warning",
                    code="stale_learning_path",
                    file=str(self.learning_settings_path),
                    message=f"Saved learning path no longer exists: {saved_path}.",
                    repairable=True,
                )
            )

        missing_sources = [
            signature
            for signature, item in processed_sources.items()
            if isinstance(item, dict) and item.get("path") and not Path(item["path"]).expanduser().exists()
        ]
        if missing_sources:
            issues.append(
                self._issue(
                    severity="warning",
                    code="stale_processed_sources",
                    file=str(self.processed_sources_path),
                    message=f"{len(missing_sources)} processed-source entries point to missing local PCAPs.",
                    repairable=False,
                )
            )

        graph_nodes = knowledge_graph.get("nodes")
        graph_edges = knowledge_graph.get("edges")
        graph_metrics = knowledge_graph.get("metrics", {})
        if not isinstance(graph_nodes, dict) or not isinstance(graph_edges, dict):
            issues.append(
                self._issue(
                    severity="error",
                    code="invalid_knowledge_graph_shape",
                    file=str(self.knowledge_graph_path),
                    message="knowledge_graph.json must store nodes and edges as dictionaries.",
                    repairable=False,
                )
            )
        else:
            expected_protocol_metrics = {
                node.get("name"): int(node.get("occurrence_count", 0))
                for node in graph_nodes.values()
                if isinstance(node, dict) and node.get("type") == "protocol"
            }
            expected_graph_metrics = {
                "node_count": len(graph_nodes),
                "edge_count": len(graph_edges),
                "protocol_count": expected_protocol_metrics,
            }
            if any(graph_metrics.get(key) != value for key, value in expected_graph_metrics.items()):
                issues.append(
                    self._issue(
                        severity="error",
                        code="knowledge_graph_metrics_out_of_sync",
                        file=str(self.knowledge_graph_path),
                        message="Knowledge-graph metrics do not match the stored nodes and edges.",
                        repairable=True,
                    )
                )

        events = timeseries.get("events", [])
        if not isinstance(events, list):
            issues.append(
                self._issue(
                    severity="error",
                    code="invalid_timeseries_shape",
                    file=str(self.timeseries_path),
                    message="timeseries_intelligence.json must store events as a list.",
                    repairable=False,
                )
            )
        else:
            expected_summary = self._detect_recurring_failures(events)
            if timeseries.get("recurring_summary") != expected_summary:
                issues.append(
                    self._issue(
                        severity="warning",
                        code="timeseries_summary_out_of_sync",
                        file=str(self.timeseries_path),
                        message="Time-series recurring summary does not match the recorded events.",
                        repairable=True,
                    )
                )

        run_report_issues = 0
        for report in state["run_reports"]:
            payload = report["payload"]
            status = payload.get("status")
            if status in {"accepted", "held", "failed"} and not payload.get("finished_at"):
                run_report_issues += 1
        if run_report_issues:
            issues.append(
                self._issue(
                    severity="warning",
                    code="stale_run_reports",
                    file=str(self.run_reports_dir),
                    message=f"Found {run_report_issues} run report(s) without finished_at for a terminal status.",
                    repairable=False,
                )
            )

        if extra_issues:
            issues.extend(issue for issue in extra_issues if issue)

        errors = [issue for issue in issues if issue["severity"] == "error"]
        warnings = [issue for issue in issues if issue["severity"] == "warning"]
        repairable_issue_count = sum(1 for issue in issues if issue.get("repairable"))
        return {
            "ok": not errors,
            "base_dir": str(self.base_dir),
            "repair_requested": repair_requested,
            "repair_applied": repair_applied,
            "repair_actions": repair_actions,
            "error_count": len(errors),
            "warning_count": len(warnings),
            "repairable_issue_count": repairable_issue_count,
            "issues": issues,
            "stats": {
                "pattern_count": len(patterns),
                "vector_count": len(vectors),
                "pending_validation_count": facts["pending_validation_count"],
                "processed_source_count": len(processed_sources),
                "run_report_count": len(state["run_reports"]),
            },
        }

    def _load_state(self) -> dict[str, Any]:
        raw_patterns = self._read_json(self.patterns_path, [])
        raw_vectors = self._read_json(self.vectors_path, [])
        raw_metrics = self._read_json(self.metrics_path, {})
        raw_validation_queue = self._read_json(self.validation_path, [])
        learning_settings = self._read_json(self.learning_settings_path, {})
        raw_processed_sources = self._read_json(self.processed_sources_path, {})
        knowledge_graph = self._read_json(self.knowledge_graph_path, {"nodes": {}, "edges": {}, "metrics": {}})
        timeseries = self._read_json(self.timeseries_path, {"events": [], "last_updated": None, "recurring_summary": {}})
        run_reports = []
        if self.run_reports_dir.exists():
            for path in sorted(self.run_reports_dir.glob("*.json")):
                run_reports.append({"path": str(path), "payload": self._read_json(path, {})})

        patterns = raw_patterns if isinstance(raw_patterns, list) else []
        vectors = raw_vectors if isinstance(raw_vectors, list) else []
        metrics = raw_metrics if isinstance(raw_metrics, dict) else {}
        validation_queue = raw_validation_queue if isinstance(raw_validation_queue, list) else []
        processed_sources = raw_processed_sources if isinstance(raw_processed_sources, dict) else {}

        pattern_ids = [
            str(entry.get("pattern_id"))
            for entry in patterns
            if isinstance(entry, dict) and entry.get("pattern_id")
        ]
        duplicate_pattern_ids = {
            item_id for item_id, count in Counter(pattern_ids).items() if count > 1
        }
        pattern_embedding_dimensions = {
            len(entry.get("embedding_vector") or [])
            for entry in patterns
            if isinstance(entry, dict) and entry.get("embedding_vector")
        }
        embedded_pattern_ids = {
            str(entry.get("pattern_id"))
            for entry in patterns
            if isinstance(entry, dict) and entry.get("pattern_id") and entry.get("embedding_vector")
        }
        vector_ids = [
            str(entry.get("id"))
            for entry in vectors
            if isinstance(entry, dict) and entry.get("id")
        ]
        vector_dimensions = {
            len(entry.get("vector") or [])
            for entry in vectors
            if isinstance(entry, dict) and entry.get("vector")
        }
        pending_keys = Counter(
            self._validation_key(item)
            for item in validation_queue
            if isinstance(item, dict) and item.get("validation_status", "pending_review") == "pending_review"
        )

        return {
            "patterns": patterns,
            "vectors": vectors,
            "metrics": metrics,
            "validation_queue": validation_queue,
            "learning_settings": learning_settings if isinstance(learning_settings, dict) else {},
            "processed_sources": processed_sources,
            "knowledge_graph": knowledge_graph if isinstance(knowledge_graph, dict) else {"nodes": {}, "edges": {}, "metrics": {}},
            "timeseries": timeseries if isinstance(timeseries, dict) else {"events": [], "last_updated": None, "recurring_summary": {}},
            "run_reports": run_reports,
            "facts": {
                "invalid_patterns_shape": self.patterns_path.exists() and not isinstance(raw_patterns, list),
                "invalid_vectors_shape": self.vectors_path.exists() and not isinstance(raw_vectors, list),
                "invalid_metrics_shape": self.metrics_path.exists() and not isinstance(raw_metrics, dict),
                "invalid_validation_shape": self.validation_path.exists() and not isinstance(raw_validation_queue, list),
                "invalid_processed_sources_shape": self.processed_sources_path.exists() and not isinstance(raw_processed_sources, dict),
                "duplicate_pattern_ids": duplicate_pattern_ids,
                "pattern_embedding_dimensions": pattern_embedding_dimensions,
                "vector_dimensions": vector_dimensions,
                "orphan_vector_ids": sorted(set(vector_ids) - set(pattern_ids)),
                "missing_vector_ids": sorted(embedded_pattern_ids - set(vector_ids)),
                "pending_validation_count": len(
                    [
                        item for item in validation_queue
                        if isinstance(item, dict) and item.get("validation_status", "pending_review") == "pending_review"
                    ]
                ),
                "approved_validation_count": len(
                    [
                        item for item in validation_queue
                        if isinstance(item, dict) and item.get("validation_status") == "approved"
                    ]
                ),
                "rejected_validation_count": len(
                    [
                        item for item in validation_queue
                        if isinstance(item, dict) and item.get("validation_status") == "rejected"
                    ]
                ),
                "duplicate_pending_validation_groups": sum(1 for count in pending_keys.values() if count > 1),
            },
        }

    @staticmethod
    def _validation_key(item: dict[str, Any]) -> tuple[Any, ...]:
        return (
            item.get("session_id"),
            item.get("pattern_id"),
            item.get("hybrid_root_cause"),
            item.get("validation_status", "pending_review"),
        )

    @staticmethod
    def _detect_recurring_failures(events: list[dict[str, Any]]) -> dict[str, Any]:
        labels = Counter(event.get("root_cause", "UNKNOWN") for event in events)
        signatures = Counter(event.get("signature") for event in events if event.get("signature"))
        recurring = [
            {"root_cause": label, "count": count}
            for label, count in sorted(labels.items(), key=lambda item: (-item[1], item[0]))
            if count >= 3 and label != "NORMAL_CALL"
        ]
        periodic = [
            {"signature": signature, "count": count}
            for signature, count in sorted(signatures.items(), key=lambda item: (-item[1], item[0]))
            if count >= 3
        ]
        return {
            "recurring_failures": recurring[:10],
            "periodic_signatures": periodic[:10],
        }

    @staticmethod
    def _issue(
        *,
        severity: str,
        code: str,
        file: str,
        message: str,
        repairable: bool,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "severity": severity,
            "code": code,
            "file": file,
            "message": message,
            "repairable": repairable,
        }
        if details:
            payload["details"] = details
        return payload

    @staticmethod
    def _read_json(path: Path, default: Any) -> Any:
        if not path.exists():
            return deepcopy(default)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return deepcopy(default)

    @staticmethod
    def _write_json(path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit or repair generated knowledge-base artifacts.")
    parser.add_argument("--base-dir", default=None, help="Override knowledge-base directory.")
    parser.add_argument("--repair", action="store_true", help="Apply safe, non-destructive repairs before re-auditing.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when unrepaired errors remain.")
    args = parser.parse_args(argv)

    doctor = KnowledgeBaseDoctor(base_dir=args.base_dir)
    report = doctor.enforce(repair=args.repair, strict=args.strict)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
