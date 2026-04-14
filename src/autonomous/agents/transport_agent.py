"""Transport/DNS/ICMP-specific RCA agent."""

from __future__ import annotations

from src.autonomous.agents.base import BaseProtocolAgent
from src.rules.rca_rules import _is_benign_icmp_cleanup


class TransportAgent(BaseProtocolAgent):
    protocol = "TRANSPORT"

    def supports(self, session: dict) -> bool:
        protocols = {str(p).upper() for p in session.get("protocols", [])}
        return bool({"TCP", "UDP", "SCTP", "DNS", "ICMP", "HTTP", "HTTPS"} & protocols)

    def analyze(self, session: dict) -> dict | None:
        features = session.get("features", {})
        dns_msgs = session.get("dns_msgs", [])
        icmp_msgs = session.get("icmp_msgs", [])
        if any("FAIL" in str(m.get("message", "")).upper() or "NXDOMAIN" in str(m.get("message", "")).upper() for m in dns_msgs):
            return {"agent": "TRANSPORT", "label": "DNS_FAILURE", "confidence": 0.86, "evidence": ["DNS resolution failure observed"]}
        if _is_benign_icmp_cleanup(session):
            return {"agent": "TRANSPORT", "label": "NORMAL_CALL", "confidence": 0.52, "evidence": ["ICMP port-unreachable observed during bearer release cleanup"]}
        if any("UNREACH" in str(m.get("message", "")).upper() for m in icmp_msgs):
            return {"agent": "TRANSPORT", "label": "CORE_NETWORK_FAILURE", "confidence": 0.79, "evidence": ["ICMP unreachable indicates path failure"]}
        if features.get("has_retransmission"):
            return {"agent": "TRANSPORT", "label": "NETWORK_CONGESTION", "confidence": 0.76, "evidence": ["Retransmissions indicate transport instability"]}
        return {"agent": "TRANSPORT", "label": "NORMAL_CALL", "confidence": 0.35, "evidence": ["Transport layer shows no dominant failure marker"]}
