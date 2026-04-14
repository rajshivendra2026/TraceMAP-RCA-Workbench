"""Infer likely root causes from weighted causal graphs."""

from __future__ import annotations

from collections import defaultdict

from src.rules.rca_rules import _legacy_mobility_profile, _lte_control_plane_profile


class CausalInferenceEngine:
    """Performs lightweight, explainable causal propagation over session graphs."""

    def infer(
        self,
        session: dict,
        graph: dict,
        agentic_result: dict | None = None,
        rule_rca: dict | None = None,
        pattern_match: dict | None = None,
    ) -> dict:
        nodes = {node["id"]: dict(node) for node in graph.get("nodes", [])}
        reverse_edges = defaultdict(list)
        for edge in graph.get("edges", []):
            reverse_edges[edge["target"]].append(edge)

        scored = []
        for node in nodes.values():
            score = 0.2
            if node.get("failure"):
                score += 0.45
            if node.get("protocol") in {"DIAMETER", "GTP", "NGAP", "NAS_5GS", "NAS_EPS", "SIP", "DNS", "ICMP"}:
                score += 0.1
            propagation = sum(float(edge.get("weight", 0)) * 0.4 for edge in reverse_edges.get(node["id"], []))
            if propagation:
                score += min(0.25, propagation)
            node["score"] = round(min(0.99, score), 4)
            scored.append(node)

        scored.sort(key=lambda item: item["score"], reverse=True)
        top_event = scored[0] if scored else None
        inferred_label = self._event_to_label(top_event, session, agentic_result, rule_rca, pattern_match)
        evidence = []
        for item in scored[:4]:
            evidence.append(f"{item['event']} contributed causal score {round(item['score'] * 100)}%")
        if pattern_match:
            evidence.append(f"Historical dependency matched {pattern_match.get('scenario', 'known pattern')}")

        return {
            "root_cause": inferred_label,
            "confidence": round((top_event or {}).get("score", 0.3), 4),
            "causal_strength": round((top_event or {}).get("score", 0.3), 4),
            "causal_chain": [
                {
                    "event": item["event"],
                    "score": item["score"],
                    "protocol": item["protocol"],
                    "failure": item["failure"],
                }
                for item in scored[:5]
            ],
            "evidence": evidence,
            "top_event": top_event["event"] if top_event else None,
        }

    def _event_to_label(self, top_event, session, agentic_result, rule_rca, pattern_match) -> str:
        if not top_event:
            return (rule_rca or {}).get("rca_label", "UNKNOWN")
        lte_profile = _lte_control_plane_profile(session or {})
        if lte_profile["successful_mobility"]:
            return "NORMAL_CALL"
        legacy_profile = _legacy_mobility_profile(session or {})
        if legacy_profile["successful_mobility"]:
            return "NORMAL_CALL"
        event = top_event.get("event", "").upper()
        if "DNS" in event and any(token in event for token in ("NXDOMAIN", "SERVFAIL", "FAIL")):
            return "DNS_FAILURE"
        if "ICMP" in event and any(token in event for token in ("UNREACH", "TIME_EXCEEDED")):
            return "CORE_NETWORK_FAILURE"
        if "DIAMETER" in event and any(token in event for token in ("5004", "ROAMING", "5003", "REJECT", "BARRED", "AUTH")):
            return "SUBSCRIBER_BARRED"
        if "DIAMETER" in event and any(token in event for token in ("4012", "CREDIT", "LIMIT")):
            return "CHARGING_FAILURE"
        if "NAS" in event and any(token in event for token in ("REJECT", "FAIL")):
            return "NETWORK_REJECTION"
        if "SIP" in event and any(token in event for token in ("487", "603")):
            return "USER_REJECTED"
        if "SIP" in event and any(token in event for token in ("408", "504", "TIMEOUT")):
            return "SERVICE_TIMEOUT"
        top_hypothesis = (agentic_result or {}).get("top_hypothesis") or {}
        if top_hypothesis.get("label"):
            return top_hypothesis["label"]
        if pattern_match and pattern_match.get("root_cause"):
            return pattern_match["root_cause"]
        return (rule_rca or {}).get("rca_label", "UNKNOWN")
