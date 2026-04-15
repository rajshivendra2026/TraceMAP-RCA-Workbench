"""Validation feedback dataset helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.config import cfg_path


def feedback_dataset_path(base_dir: str | Path | None = None) -> Path:
    if base_dir is not None:
        return Path(base_dir) / "feedback_dataset.jsonl"
    return Path(cfg_path("learning.feedback_dataset_path", "data/knowledge_base/feedback_dataset.jsonl"))


def append_feedback_record(record: dict[str, Any], *, base_dir: str | Path | None = None) -> Path:
    target = feedback_dataset_path(base_dir=base_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")
    return target


def load_feedback_records(path: str | Path | None = None) -> list[dict[str, Any]]:
    target = Path(path) if path is not None else feedback_dataset_path()
    if not target.exists():
        return []

    rows: list[dict[str, Any]] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def feedback_record_to_session(record: dict[str, Any]) -> dict[str, Any] | None:
    snapshot = record.get("session_snapshot") or {}
    if not snapshot:
        return None

    confidence_pct = snapshot.get("confidence_pct", 0)
    priority_score = snapshot.get("priority_score", 0)
    approved = str(record.get("review_action", "")).lower() == "approve"
    rca_label = (
        record.get("resolved_root_cause")
        or snapshot.get("rca_label")
        or record.get("hybrid_root_cause")
        or record.get("knowledge_root_cause")
        or record.get("rule_root_cause")
        or "UNKNOWN"
    )

    session = {
        "session_id": snapshot.get("session_id") or record.get("session_id"),
        "protocols": snapshot.get("protocols", []),
        "technologies": snapshot.get("technologies", []),
        "duration_ms": snapshot.get("duration_ms", 0),
        "features": snapshot.get("features", {}),
        "trace_intelligence": snapshot.get("trace_intelligence", {}),
        "hybrid_rca": {
            "rca_label": rca_label,
            "confidence_pct": confidence_pct,
            "raw_confidence_pct": snapshot.get("raw_confidence_pct", confidence_pct),
            "priority_score": priority_score,
            "priority_band": snapshot.get("priority_band", "low"),
            "priority_reason": snapshot.get("priority_reason", "feedback retraining"),
            "pattern_match": snapshot.get("pattern_match", {}),
            "anomaly": snapshot.get("anomaly", {}),
            "confidence_model": snapshot.get("confidence_model", {}),
        },
        "priority_label": float(priority_score) if approved else min(99.0, max(float(priority_score), 82.0)),
        "confidence_label": 1 if approved else 0,
    }
    return session


def build_feedback_training_sessions(path: str | Path | None = None) -> list[dict[str, Any]]:
    sessions: list[dict[str, Any]] = []
    for record in load_feedback_records(path):
        session = feedback_record_to_session(record)
        if session:
            sessions.append(session)
    return sessions
