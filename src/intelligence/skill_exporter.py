"""Portable export of high-value learned RCA patterns."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from src.config import cfg_path
from src.intelligence.knowledge_engine import KnowledgeEngine


class SkillExporter:
    def __init__(self, knowledge_engine: KnowledgeEngine, output_dir: str | None = None):
        self.knowledge_engine = knowledge_engine
        self.output_dir = Path(output_dir or cfg_path("data.skill_files", "data/skill_files"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, min_confidence: float = 0.75, top_n: int = 200) -> str:
        patterns = [
            row for row in self.knowledge_engine.list_patterns()
            if float(row.get("confidence", 0)) >= min_confidence
            and row.get("validation_status") in {"validated", "auto_validated"}
        ]
        patterns.sort(
            key=lambda row: (
                float(row.get("confidence", 0)),
                int(row.get("occurrence_count", 0)),
            ),
            reverse=True,
        )
        exported = []
        for row in patterns[:top_n]:
            exported.append(
                {
                    "pattern_id": row.get("pattern_id"),
                    "protocols": row.get("protocols", []),
                    "scenario": row.get("scenario"),
                    "root_cause": row.get("root_cause"),
                    "confidence": row.get("confidence"),
                    "occurrence_count": row.get("occurrence_count"),
                    "last_seen": row.get("last_seen"),
                    "evidence_template": row.get("evidence_template"),
                    "context": row.get("context", {}),
                    "embedding_vector": [round(float(v), 6) for v in row.get("embedding_vector", [])],
                }
            )

        payload = {
            "version": datetime.now(timezone.utc).strftime("%Y.%m.%d"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "pattern_count": len(exported),
            "patterns": exported,
        }
        name = f"rca_skill_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
        target = self.output_dir / name
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        (self.output_dir / "latest.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(target)
