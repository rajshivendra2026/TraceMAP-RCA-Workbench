"""Knowledge base compaction and lifecycle management."""

from __future__ import annotations

from datetime import datetime, timezone

from src.intelligence.knowledge_engine import KnowledgeEngine


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _cosine(a: list[float], b: list[float]) -> float:
    size = min(len(a), len(b))
    if size == 0:
        return 0.0
    return sum(float(a[i]) * float(b[i]) for i in range(size))


class KnowledgeCompactor:
    """Reduces noise, merges near-duplicates, and applies time decay."""

    def __init__(self, knowledge_engine: KnowledgeEngine):
        self.knowledge_engine = knowledge_engine

    def compact(
        self,
        similarity_threshold: float = 0.94,
        min_confidence: float = 0.35,
        stale_after_days: int = 45,
    ) -> dict:
        now = datetime.now(timezone.utc)
        retained = []
        removed = []

        for entry in sorted(
            self.knowledge_engine.list_patterns(),
            key=lambda row: (row.get("root_cause"), -float(row.get("confidence", 0))),
        ):
            age_days = self._age_days(entry, now)
            decayed_conf = self._decayed_confidence(entry, age_days)
            entry["confidence"] = round(decayed_conf, 4)
            if decayed_conf < min_confidence or age_days > stale_after_days and entry.get("occurrence_count", 0) <= 1:
                removed.append(entry["pattern_id"])
                continue

            merged = False
            for existing in retained:
                if existing.get("root_cause") != entry.get("root_cause"):
                    continue
                if set(existing.get("protocols", [])) != set(entry.get("protocols", [])):
                    continue
                if _cosine(existing.get("embedding_vector", []), entry.get("embedding_vector", [])) < similarity_threshold:
                    continue
                self._merge(existing, entry)
                merged = True
                break
            if not merged:
                retained.append(entry)

        self.knowledge_engine.replace_patterns(retained)
        if removed:
            self.knowledge_engine.vector_store.delete(removed)
        self.knowledge_engine.metrics["last_compaction"] = now.isoformat()
        self.knowledge_engine.metrics["pattern_count"] = len(retained)
        self.knowledge_engine.save()
        return {
            "retained": len(retained),
            "removed": len(removed),
            "removed_pattern_ids": removed,
        }

    def _merge(self, base: dict, incoming: dict) -> None:
        base["occurrence_count"] = int(base.get("occurrence_count", 0)) + int(incoming.get("occurrence_count", 0))
        base["confidence"] = round(max(float(base.get("confidence", 0)), float(incoming.get("confidence", 0))), 4)
        base["last_seen"] = max(base.get("last_seen", ""), incoming.get("last_seen", ""))
        base["historical_success"] = round(
            max(float(base.get("historical_success", 0.5)), float(incoming.get("historical_success", 0.5))),
            4,
        )
        base["source_sessions"] = sorted(set(base.get("source_sessions", [])) | set(incoming.get("source_sessions", [])))[:25]
        if incoming.get("signature") and len(incoming["signature"]) > len(base.get("signature", [])):
            base["signature"] = incoming["signature"]
        if incoming.get("scenario") and base.get("scenario", "").lower().startswith("generic"):
            base["scenario"] = incoming["scenario"]
        self.knowledge_engine.vector_store.upsert(
            base["pattern_id"],
            base.get("embedding_vector", []),
            {
                "root_cause": base.get("root_cause"),
                "validation_status": base.get("validation_status"),
            },
        )

    @staticmethod
    def _age_days(entry: dict, now: datetime) -> int:
        ts = _parse_ts(entry.get("last_seen"))
        if not ts:
            return 0
        return max(0, (now - ts).days)

    @staticmethod
    def _decayed_confidence(entry: dict, age_days: int) -> float:
        confidence = float(entry.get("confidence", 0.5))
        occurrence = max(1, int(entry.get("occurrence_count", 1)))
        decay = max(0.65, 1 - (age_days / 365))
        reinforcement = min(1.15, 1 + (occurrence / 50))
        return min(0.995, confidence * decay * reinforcement)
