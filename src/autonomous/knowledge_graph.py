"""Structured telecom knowledge graph built from sessions and RCA outcomes."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from src.autonomous.graph_store import GraphStore


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(text: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in str(text or "")).strip("-") or "unknown"


class TelecomKnowledgeGraph:
    """A lightweight Neo4j-compatible graph model backed by JSON."""

    def __init__(self, store: GraphStore | None = None):
        self.store = store or GraphStore()
        payload = self.store.load()
        self.nodes: dict[str, dict[str, Any]] = payload.get("nodes", {})
        self.edges: dict[str, dict[str, Any]] = payload.get("edges", {})
        self.metrics: dict[str, Any] = payload.get("metrics", {})

    def upsert_node(self, node_type: str, name: str, attributes: dict | None = None) -> str:
        node_id = f"{node_type}:{_slug(name)}"
        row = self.nodes.setdefault(
            node_id,
            {
                "id": node_id,
                "type": node_type,
                "name": name,
                "attributes": {},
                "weight": 0.0,
                "occurrence_count": 0,
                "last_seen": None,
            },
        )
        row["name"] = name
        row["occurrence_count"] += 1
        row["weight"] = round(float(row.get("weight", 0.0)) + 1.0, 4)
        row["last_seen"] = _utc_now()
        if attributes:
            row["attributes"].update(attributes)
        return node_id

    def add_relation(
        self,
        source_id: str,
        relation: str,
        target_id: str,
        weight: float = 1.0,
        attributes: dict | None = None,
    ) -> str:
        edge_id = f"{source_id}|{relation}|{target_id}"
        row = self.edges.setdefault(
            edge_id,
            {
                "id": edge_id,
                "source": source_id,
                "target": target_id,
                "relation": relation,
                "weight": 0.0,
                "occurrence_count": 0,
                "last_seen": None,
                "attributes": {},
            },
        )
        row["occurrence_count"] += 1
        row["weight"] = round(float(row.get("weight", 0.0)) + float(weight), 4)
        row["last_seen"] = _utc_now()
        if attributes:
            row["attributes"].update(attributes)
        return edge_id

    def get_relation_weight(self, source_name: str, relation: str, target_name: str) -> float:
        edge_id = f"{source_name}|{relation}|{target_name}"
        return float(self.edges.get(edge_id, {}).get("weight", 0.0))

    def update_from_session(
        self,
        session: dict,
        final_rca: dict | None = None,
        agentic: dict | None = None,
        causal: dict | None = None,
    ) -> dict:
        protocols = session.get("protocols", [])
        technologies = session.get("technologies", [])
        flow = session.get("flow", [])
        protocol_nodes = []
        for protocol in protocols:
            protocol_nodes.append(self.upsert_node("protocol", str(protocol).upper()))
        tech_nodes = [self.upsert_node("technology", tech) for tech in technologies]
        scenario_name = (
            (final_rca or {}).get("rca_title")
            or session.get("rca", {}).get("rca_title")
            or session.get("rca", {}).get("rca_label")
            or "Unknown Scenario"
        )
        scenario_id = self.upsert_node("scenario", scenario_name, {"session_id": session.get("session_id")})
        error_id = self.upsert_node(
            "error",
            (final_rca or {}).get("rca_label") or session.get("rca", {}).get("rca_label", "UNKNOWN"),
        )
        self.add_relation(scenario_id, "causes", error_id, weight=max(1.0, float((final_rca or {}).get("confidence_pct", 40)) / 25))
        for node_id in protocol_nodes:
            self.add_relation(node_id, "participates_in", scenario_id, weight=1.0)
        for tech_id in tech_nodes:
            self.add_relation(tech_id, "depends_on", scenario_id, weight=0.7)

        prev_event_id = None
        for item in flow:
            protocol = str(item.get("protocol", "UNKNOWN")).upper()
            message = str(item.get("message") or item.get("short_label") or "EVENT")
            event_name = f"{protocol}:{message}"
            event_id = self.upsert_node(
                "event",
                event_name,
                {
                    "protocol": protocol,
                    "message": message,
                    "src": item.get("src"),
                    "dst": item.get("dst"),
                },
            )
            self.add_relation(scenario_id, "contains", event_id, weight=1.0)
            if prev_event_id:
                self.add_relation(prev_event_id, "precedes", event_id, weight=1.0)
            prev_event_id = event_id
            if item.get("failure") or "reject" in message.lower() or "fail" in message.lower():
                self.add_relation(event_id, "correlates_with", error_id, weight=1.2)

        if agentic:
            for hypothesis in agentic.get("hypotheses", []):
                label = hypothesis.get("label", "UNKNOWN")
                hyp_id = self.upsert_node("hypothesis", f"{hypothesis.get('agent')}:{label}")
                self.add_relation(hyp_id, "correlates_with", error_id, weight=hypothesis.get("confidence", 0.5))
                self.add_relation(scenario_id, "depends_on", hyp_id, weight=0.8)

        if causal:
            for hop in causal.get("causal_chain", [])[:5]:
                cause_node = self.upsert_node("event", hop.get("event", "UNKNOWN"))
                self.add_relation(cause_node, "causes", error_id, weight=hop.get("score", 0.5))

        self.metrics["node_count"] = len(self.nodes)
        self.metrics["edge_count"] = len(self.edges)
        self.metrics["protocol_count"] = dict(Counter(node["name"] for node in self.nodes.values() if node.get("type") == "protocol"))
        self.save()
        return self.summary()

    def update_from_pattern(self, pattern: dict) -> None:
        scenario_id = self.upsert_node("scenario", pattern.get("scenario", "Unknown Pattern"))
        error_id = self.upsert_node("error", pattern.get("root_cause", "UNKNOWN"))
        self.add_relation(scenario_id, "causes", error_id, weight=pattern.get("confidence", 0.5))
        for protocol in pattern.get("protocols", []):
            protocol_id = self.upsert_node("protocol", protocol)
            self.add_relation(protocol_id, "participates_in", scenario_id, weight=1.0)
        for signature in pattern.get("signature", []):
            event_id = self.upsert_node("event", signature)
            self.add_relation(scenario_id, "contains", event_id, weight=1.0)
        self.save()

    def summary(self) -> dict:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "top_errors": Counter(
                node["name"] for node in self.nodes.values() if node.get("type") == "error"
            ).most_common(5),
            "top_protocols": Counter(
                node["name"] for node in self.nodes.values() if node.get("type") == "protocol"
            ).most_common(5),
        }

    def save(self) -> None:
        self.store.save(self.nodes, self.edges, self.metrics)
