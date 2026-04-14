"""Persistent storage for graph-backed RCA knowledge."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from src.config import cfg_path


class GraphStore:
    """Stores graph nodes and edges as portable JSON."""

    def __init__(self, base_dir: str | None = None):
        self.base_dir = Path(base_dir or cfg_path("data.knowledge_base", "data/knowledge_base"))
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.base_dir / "knowledge_graph.json"
        self.data = self._read()

    def load(self) -> dict:
        self.data = self._read()
        return deepcopy(self.data)

    def save(self, nodes: dict, edges: dict, metrics: dict | None = None) -> None:
        self.data = {
            "nodes": nodes,
            "edges": edges,
            "metrics": metrics or {},
        }
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def _read(self) -> dict:
        if not self.path.exists():
            return {"nodes": {}, "edges": {}, "metrics": {}}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {"nodes": {}, "edges": {}, "metrics": {}}
