"""Persistent RCA knowledge base for pattern reuse and retrieval."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from src.config import cfg_path
from src.eval.feedback_dataset import append_feedback_record
from src.intelligence.vector_store import VectorStore


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


DEFAULT_METRICS: dict[str, Any] = {
    "pattern_reuse_count": 0,
    "candidate_pattern_count": 0,
    "validation_queue_size": 0,
    "validated_count": 0,
    "rejected_count": 0,
    "last_compaction": None,
    "pattern_count": 0,
}


class KnowledgeEngine:
    """Hybrid JSON plus vector storage for telecom RCA patterns."""

    def __init__(self, base_dir: str | None = None):
        self.base_dir = Path(base_dir or cfg_path("data.knowledge_base", "data/knowledge_base"))
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.patterns_path = self.base_dir / "patterns.json"
        self.validation_path = self.base_dir / "validation_queue.json"
        self.metrics_path = self.base_dir / "metrics.json"
        self.vector_store = VectorStore(self.base_dir / "vectors.json")

        self.patterns: list[dict[str, Any]] = self._read_json(self.patterns_path, [])
        self.validation_queue: list[dict[str, Any]] = self._read_json(self.validation_path, [])
        self.metrics: dict[str, Any] = self._read_json(self.metrics_path, DEFAULT_METRICS)
        self._synchronize_state()
        self.save()

    def query_similar(
        self,
        embedding: list[float],
        protocols: list[str] | None = None,
        context: dict | None = None,
        top_k: int = 5,
    ) -> list[dict]:
        protocols = sorted({str(p).upper() for p in (protocols or [])})
        matches = self.vector_store.query(embedding, top_k=max(top_k * 2, top_k))
        enriched = []
        for match in matches:
            entry = self.get_pattern(match["id"])
            if not entry:
                continue
            if protocols and not set(protocols).intersection(set(entry.get("protocols", []))):
                continue
            if context and not self._context_compatible(entry.get("context", {}), context):
                continue
            row = deepcopy(entry)
            row["similarity"] = round(float(match["score"]), 4)
            enriched.append(row)
            if len(enriched) >= top_k:
                break
        return enriched

    def reinforce_pattern(self, pattern_id: str, confidence_delta: float = 0.02) -> dict | None:
        entry = self.get_pattern(pattern_id)
        if not entry:
            return None
        entry["occurrence_count"] = int(entry.get("occurrence_count", 0)) + 1
        entry["confidence"] = round(min(0.995, float(entry.get("confidence", 0.5)) + confidence_delta), 4)
        entry["last_seen"] = utc_now()
        if entry.get("validation_status") == "candidate" and entry["occurrence_count"] >= 3:
            entry["validation_status"] = "auto_validated"
        self.metrics["pattern_reuse_count"] = int(self.metrics.get("pattern_reuse_count", 0)) + 1
        self.save()
        return entry

    def add_candidate_pattern(self, entry: dict) -> dict:
        payload = {
            "pattern_id": entry.get("pattern_id") or f"pat-{uuid4().hex[:12]}",
            "protocols": sorted({str(p).upper() for p in entry.get("protocols", [])}),
            "scenario": entry.get("scenario", "Generic Telecom Failure"),
            "signature": entry.get("signature", []),
            "root_cause": entry.get("root_cause", "UNKNOWN"),
            "confidence": round(float(entry.get("confidence", 0.45)), 4),
            "occurrence_count": int(entry.get("occurrence_count", 1)),
            "last_seen": entry.get("last_seen") or utc_now(),
            "evidence_template": entry.get("evidence_template", ""),
            "embedding_vector": [float(v) for v in entry.get("embedding_vector", [])],
            "context": entry.get("context", {}),
            "historical_success": float(entry.get("historical_success", 0.55)),
            "validation_status": entry.get("validation_status", "candidate"),
            "source_sessions": entry.get("source_sessions", []),
            "anomaly_profile": entry.get("anomaly_profile", {}),
        }
        existing = self.get_pattern(payload["pattern_id"])
        if existing:
            existing.update(payload)
        else:
            self.patterns.append(payload)
        self.vector_store.upsert(
            payload["pattern_id"],
            payload["embedding_vector"],
            {
                "root_cause": payload["root_cause"],
                "validation_status": payload["validation_status"],
            },
        )
        self.save()
        return payload

    def queue_validation(self, item: dict) -> None:
        payload = dict(item)
        payload.setdefault("validation_id", f"val-{uuid4().hex[:12]}")
        payload.setdefault("queued_at", utc_now())
        payload.setdefault("validation_status", "pending_review")
        existing = self._find_pending_validation(payload)
        if existing:
            self._merge_validation_items(existing, payload)
        else:
            self.validation_queue.append(payload)
        self.save()

    def resolve_validation(
        self,
        validation_id: str,
        action: str,
        reviewer: str = "user",
        note: str | None = None,
    ) -> dict | None:
        action = str(action or "").lower()
        if action not in {"approve", "reject", "defer"}:
            raise ValueError("action must be approve, reject, or defer")

        self._normalize_validation_queue()
        item = next((row for row in self.validation_queue if row.get("validation_id") == validation_id), None)
        if not item:
            return None

        status_map = {
            "approve": "approved",
            "reject": "rejected",
            "defer": "deferred",
        }
        item["validation_status"] = status_map[action]
        item["reviewed_at"] = utc_now()
        item["reviewer"] = reviewer
        if note:
            item["review_note"] = note
        item["review_action"] = action
        item["resolved_root_cause"] = (
            item.get("hybrid_root_cause")
            if action == "approve"
            else item.get("knowledge_root_cause") or item.get("rule_root_cause") or item.get("hybrid_root_cause")
        )

        pattern_id = item.get("pattern_id")
        if action == "approve" and pattern_id:
            pattern = self.get_pattern(pattern_id)
            if pattern:
                pattern["validation_status"] = "validated"
                approved_root = item.get("hybrid_root_cause") or item.get("knowledge_root_cause") or pattern.get("root_cause")
                if approved_root:
                    pattern["root_cause"] = approved_root
                pattern["last_seen"] = utc_now()
        elif action == "reject" and pattern_id:
            pattern = self.get_pattern(pattern_id)
            if pattern:
                pattern["validation_status"] = "needs_review"
                pattern["confidence"] = round(max(0.2, float(pattern.get("confidence", 0.5)) - 0.08), 4)

        append_feedback_record(
            {
                "validation_id": item.get("validation_id"),
                "session_id": item.get("session_id"),
                "pattern_id": item.get("pattern_id"),
                "review_action": action,
                "validation_status": item.get("validation_status"),
                "reviewer": reviewer,
                "review_note": note,
                "reviewed_at": item.get("reviewed_at"),
                "rule_root_cause": item.get("rule_root_cause"),
                "hybrid_root_cause": item.get("hybrid_root_cause"),
                "knowledge_root_cause": item.get("knowledge_root_cause"),
                "resolved_root_cause": item.get("resolved_root_cause"),
                "similarity": item.get("similarity"),
                "confidence_score": item.get("confidence_score"),
                "uncertainty": item.get("uncertainty"),
                "agent_conflict": item.get("agent_conflict"),
                "context": item.get("context"),
                "session_snapshot": item.get("session_snapshot"),
            },
            base_dir=self.base_dir,
        )
        self.save()
        return deepcopy(item)

    def get_pattern(self, pattern_id: str) -> dict | None:
        return next((entry for entry in self.patterns if entry.get("pattern_id") == pattern_id), None)

    def list_patterns(self) -> list[dict]:
        return list(self.patterns)

    def replace_patterns(self, patterns: list[dict]) -> None:
        self.patterns = patterns
        self.save()

    def save(self) -> None:
        self._synchronize_state()
        self._write_json(self.patterns_path, self.patterns)
        self._write_json(self.validation_path, self.validation_queue)
        self._write_json(self.metrics_path, self.metrics)
        self.vector_store.save()

    def build_context(self, session: dict, intelligence: dict) -> dict:
        technologies = sorted({str(t) for t in session.get("technologies", [])})
        protocols = sorted({str(p).upper() for p in session.get("protocols", [])})
        roaming = "ROAMING" if any(token in (session.get("pcap_source", "") or "").upper() for token in ("ROAM", "VISITED")) else "HOME"
        vendor = "UNKNOWN"
        for node in [item.get("src") for item in session.get("flow", [])] + [item.get("dst") for item in session.get("flow", [])]:
            text = str(node or "")
            if "HUAWEI" in text.upper():
                vendor = "HUAWEI"
                break
            if "NOKIA" in text.upper():
                vendor = "NOKIA"
                break
            if "ERICSSON" in text.upper():
                vendor = "ERICSSON"
                break
        return {
            "network_scope": roaming,
            "protocol_stack": protocols,
            "technology_family": technologies,
            "vendor": vendor,
            "call_type": intelligence.get("call_type", "Generic Session"),
        }

    def _context_compatible(self, stored: dict, incoming: dict) -> bool:
        if not stored:
            return True
        for key in ("network_scope", "vendor", "call_type"):
            value = stored.get(key)
            if value and incoming.get(key) and value != incoming.get(key):
                return False
        for key in ("protocol_stack", "technology_family"):
            expected = set(stored.get(key, []))
            seen = set(incoming.get(key, []))
            if expected and seen and expected.isdisjoint(seen):
                return False
        return True

    def _synchronize_state(self) -> None:
        self._normalize_validation_queue()
        self._sync_vector_store()
        self._refresh_metrics()

    def _normalize_validation_queue(self) -> None:
        changed = False
        normalized: list[dict[str, Any]] = []
        pending_index: dict[tuple[Any, ...], dict[str, Any]] = {}
        for item in self.validation_queue:
            if not item.get("validation_id"):
                item["validation_id"] = f"val-{uuid4().hex[:12]}"
                changed = True
            item.setdefault("validation_status", "pending_review")
            if item.get("validation_status") != "pending_review":
                normalized.append(item)
                continue
            key = self._validation_key(item)
            existing = pending_index.get(key)
            if existing is None:
                pending_index[key] = item
                normalized.append(item)
                continue
            self._merge_validation_items(existing, item)
            changed = True
        if changed or len(normalized) != len(self.validation_queue):
            self.validation_queue = normalized

    def _sync_vector_store(self) -> None:
        pattern_rows = {
            entry["pattern_id"]: entry
            for entry in self.patterns
            if entry.get("pattern_id")
        }
        expected_dims = {
            len(entry.get("embedding_vector") or [])
            for entry in pattern_rows.values()
            if entry.get("embedding_vector")
        }
        if len(expected_dims) > 1:
            raise ValueError(f"inconsistent pattern embedding dimensions: {sorted(expected_dims)}")

        expected_dim = next(iter(expected_dims), None)
        records = self.vector_store.items()
        current_dim = len(records[0]["vector"]) if records else None
        if expected_dim is not None and current_dim is not None and expected_dim != current_dim:
            if self.vector_store.path.exists():
                self.vector_store.path.unlink()
            self.vector_store = VectorStore(self.base_dir / "vectors.json")
            records = []

        stale_ids = [
            row["id"]
            for row in records
            if row.get("id") not in pattern_rows or not pattern_rows[row["id"]].get("embedding_vector")
        ]
        if stale_ids:
            self.vector_store.delete(stale_ids)

        current = {row["id"]: row for row in self.vector_store.items()}
        for pattern_id, entry in pattern_rows.items():
            vector = entry.get("embedding_vector") or []
            if not vector:
                continue
            metadata = {
                "root_cause": entry.get("root_cause"),
                "validation_status": entry.get("validation_status"),
            }
            stored = current.get(pattern_id)
            if stored is None or stored.get("metadata") != metadata:
                self.vector_store.upsert(pattern_id, vector, metadata)

    def _refresh_metrics(self) -> None:
        merged = dict(DEFAULT_METRICS)
        merged.update(self.metrics)
        merged["pattern_count"] = len(self.patterns)
        merged["candidate_pattern_count"] = len(self.vector_store.items())
        merged["validation_queue_size"] = len(
            [row for row in self.validation_queue if row.get("validation_status") == "pending_review"]
        )
        merged["validated_count"] = len(
            [row for row in self.validation_queue if row.get("validation_status") == "approved"]
        )
        merged["rejected_count"] = len(
            [row for row in self.validation_queue if row.get("validation_status") == "rejected"]
        )
        self.metrics = merged

    def _find_pending_validation(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        key = self._validation_key(payload)
        for item in self.validation_queue:
            if item.get("validation_status", "pending_review") != "pending_review":
                continue
            if self._validation_key(item) == key:
                return item
        return None

    def _merge_validation_items(self, target: dict[str, Any], incoming: dict[str, Any]) -> None:
        for key, value in incoming.items():
            if key in {"validation_id", "queued_at"} or value in (None, "", [], {}):
                continue
            target[key] = value
        target.setdefault("queued_at", incoming.get("queued_at") or utc_now())

    @staticmethod
    def _validation_key(item: dict[str, Any]) -> tuple[Any, ...]:
        return (
            item.get("session_id"),
            item.get("pattern_id"),
            item.get("hybrid_root_cause"),
            item.get("validation_status", "pending_review"),
        )

    @staticmethod
    def _read_json(path: Path, default):
        if not path.exists():
            return deepcopy(default)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return deepcopy(default)

    @staticmethod
    def _write_json(path: Path, payload) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
