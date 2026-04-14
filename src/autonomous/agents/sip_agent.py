"""SIP/IMS-specific RCA agent."""

from __future__ import annotations

from src.autonomous.agents.base import BaseProtocolAgent


class SIPAgent(BaseProtocolAgent):
    protocol = "SIP"

    def analyze(self, session: dict) -> dict | None:
        msgs = session.get("sip_msgs", []) or [item for item in session.get("flow", []) if str(item.get("protocol", "")).upper() == "SIP"]
        if not msgs:
            return None
        codes = {str(m.get("message") or m.get("sip_code") or "") for m in msgs}
        if "487" in codes or "603" in codes:
            return {"agent": "SIP", "label": "USER_REJECTED", "confidence": 0.82, "evidence": ["SIP decline/cancel final response detected"]}
        if "408" in codes or "504" in codes:
            return {"agent": "SIP", "label": "SERVICE_TIMEOUT", "confidence": 0.8, "evidence": ["SIP timeout response detected"]}
        if "486" in codes:
            return {"agent": "SIP", "label": "USER_BUSY", "confidence": 0.82, "evidence": ["Busy response returned by destination"]}
        return {"agent": "SIP", "label": "NORMAL_CALL", "confidence": 0.45, "evidence": ["No terminal SIP failure observed"]}
