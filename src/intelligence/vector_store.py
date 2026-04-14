"""Vector store with FAISS-first, pure-Python fallback behavior."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Iterable

try:  # pragma: no cover - optional dependency
    import faiss  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    faiss = None


def _normalize(vector: Iterable[float]) -> list[float]:
    values = [float(v) for v in vector]
    norm = math.sqrt(sum(v * v for v in values)) or 1.0
    return [v / norm for v in values]


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b:
        return 0.0
    size = min(len(a), len(b))
    return sum(a[i] * b[i] for i in range(size))


class VectorStore:
    """Small production-safe vector index used for RCA pattern similarity."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[dict] = []
        self._index = None
        self._load()

    def upsert(self, item_id: str, vector: Iterable[float], metadata: dict | None = None) -> None:
        normalized = _normalize(vector)
        record = {
            "id": item_id,
            "vector": normalized,
            "metadata": metadata or {},
        }
        existing = next((i for i, row in enumerate(self._records) if row["id"] == item_id), None)
        if existing is None:
            self._records.append(record)
        else:
            self._records[existing] = record
        self._rebuild()
        self.save()

    def delete(self, item_ids: Iterable[str]) -> None:
        target = set(item_ids)
        if not target:
            return
        self._records = [row for row in self._records if row["id"] not in target]
        self._rebuild()
        self.save()

    def query(
        self,
        vector: Iterable[float],
        top_k: int = 5,
        metadata_filter: dict | None = None,
    ) -> list[dict]:
        if not self._records:
            return []

        normalized = _normalize(vector)
        candidates = self._records
        if metadata_filter:
            candidates = [
                row for row in candidates
                if all(row.get("metadata", {}).get(key) == value for key, value in metadata_filter.items())
            ]
            if not candidates:
                return []

        if self._index is not None and faiss is not None and candidates is self._records:  # pragma: no cover - optional
            import numpy as np

            query = np.array([normalized], dtype="float32")
            scores, indices = self._index.search(query, min(top_k, len(self._records)))
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < 0:
                    continue
                row = self._records[int(idx)]
                results.append(
                    {
                        "id": row["id"],
                        "score": float(score),
                        "metadata": row.get("metadata", {}),
                    }
                )
            return results

        scored = []
        for row in candidates:
            scored.append(
                {
                    "id": row["id"],
                    "score": _cosine(normalized, row["vector"]),
                    "metadata": row.get("metadata", {}),
                }
            )
        scored.sort(key=lambda item: item["score"], reverse=True)
        return scored[:top_k]

    def get(self, item_id: str) -> dict | None:
        return next((row for row in self._records if row["id"] == item_id), None)

    def items(self) -> list[dict]:
        return list(self._records)

    def save(self) -> None:
        self.path.write_text(json.dumps(self._records, indent=2), encoding="utf-8")

    def _load(self) -> None:
        if not self.path.exists():
            self._records = []
            return
        try:
            self._records = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            self._records = []
        self._rebuild()

    def _rebuild(self) -> None:
        if faiss is None or not self._records:  # pragma: no cover - optional dependency
            self._index = None
            return

        import numpy as np

        dim = len(self._records[0]["vector"])
        index = faiss.IndexFlatIP(dim)
        matrix = np.array([row["vector"] for row in self._records], dtype="float32")
        index.add(matrix)
        self._index = index
