"""Build per-session causal graphs from normalized telecom events."""

from __future__ import annotations

import math


class CausalGraphEngine:
    """Converts ordered session flow into a weighted causal graph."""

    def __init__(self, temporal_window_ms: float = 5000.0):
        self.temporal_window_ms = temporal_window_ms

    def build_session_graph(self, session: dict, knowledge_graph=None) -> dict:
        flow = session.get("flow", [])
        nodes = []
        edges = []
        previous = None
        previous_ts = None

        for idx, item in enumerate(flow):
            protocol = str(item.get("protocol", "UNKNOWN")).upper()
            message = str(item.get("message") or item.get("short_label") or "EVENT")
            timestamp = self._safe_ms(item.get("time"))
            node_id = f"evt-{idx}"
            node = {
                "id": node_id,
                "event": f"{protocol}:{message}",
                "protocol": protocol,
                "message": message,
                "timestamp_ms": timestamp,
                "src": item.get("src"),
                "dst": item.get("dst"),
                "failure": bool(
                    item.get("failure")
                    or "reject" in message.lower()
                    or "fail" in message.lower()
                    or message.isdigit() and int(message) >= 300
                ),
            }
            nodes.append(node)

            if previous:
                gap_ms = max(0.0, timestamp - (previous_ts or timestamp))
                temporal_weight = max(0.05, math.exp(-(gap_ms / max(self.temporal_window_ms, 1.0))))
                learned_weight = 0.0
                if knowledge_graph is not None:
                    learned_weight = knowledge_graph.get_relation_weight(
                        f"event:{previous['event'].lower().replace(' ', '-')}",
                        "precedes",
                        f"event:{node['event'].lower().replace(' ', '-')}",
                    )
                    learned_weight = min(1.0, learned_weight / 10.0)
                relation_weight = round(min(0.99, temporal_weight + learned_weight), 4)
                edges.append(
                    {
                        "source": previous["id"],
                        "target": node_id,
                        "type": "precedes",
                        "weight": relation_weight,
                        "gap_ms": round(gap_ms, 3),
                    }
                )
            previous = node
            previous_ts = timestamp

        return {"nodes": nodes, "edges": edges}

    @staticmethod
    def _safe_ms(value) -> float:
        try:
            return float(value) * 1000.0
        except (TypeError, ValueError):
            return 0.0
