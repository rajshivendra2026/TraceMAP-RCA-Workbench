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
    if not values:
        return []
    norm = math.sqrt(sum(v * v for v in values)) or 1.0
    return [v / norm for v in values]


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b:
        return 0.0
    if len(a) != len(b):
        raise ValueError(f"vector dimension mismatch: {len(a)} != {len(b)}")
    return sum(a[i] * b[i] for i in range(len(a)))


class VectorStore:
    """Small production-safe vector index used for RCA pattern similarity."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[dict] = []
        self._index = None
        self.dimension: int | None = None
        self._load()

    def upsert(self, item_id: str, vector: Iterable[float], metadata: dict | None = None) -> None:
        normalized = _normalize(vector)
        self._ensure_dimension(normalized)
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
        if not self._records:
            self.dimension = None
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
        if self.dimension is not None and normalized and len(normalized) != self.dimension:
            raise ValueError(
                f"query vector dimension mismatch: expected {self.dimension}, got {len(normalized)}"
            )
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
            self.dimension = None
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            payload = []
        self._records = self._coerce_records(payload)
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

    def _ensure_dimension(self, vector: list[float]) -> None:
        if not vector:
            return
        if self.dimension is None:
            self.dimension = len(vector)
            return
        if len(vector) != self.dimension:
            raise ValueError(
                f"vector dimension mismatch: expected {self.dimension}, got {len(vector)}"
            )

    def _coerce_records(self, payload) -> list[dict]:
        if not isinstance(payload, list):
            self.dimension = None
            return []

        records: list[dict] = []
        expected_dim: int | None = None
        for row in payload:
            if not isinstance(row, dict):
                continue
            item_id = row.get("id")
            vector = row.get("vector")
            if not item_id or not isinstance(vector, list):
                continue
            normalized = _normalize(vector)
            if not normalized:
                continue
            if expected_dim is None:
                expected_dim = len(normalized)
            elif len(normalized) != expected_dim:
                self.dimension = None
                return []
            records.append(
                {
                    "id": str(item_id),
                    "vector": normalized,
                    "metadata": row.get("metadata") if isinstance(row.get("metadata"), dict) else {},
                }
            )

        self.dimension = expected_dim
        return records
