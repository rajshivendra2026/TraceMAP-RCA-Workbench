"""GTP/PFCP-specific RCA agent."""

from __future__ import annotations

from src.autonomous.agents.base import BaseProtocolAgent


class GTPAgent(BaseProtocolAgent):
    protocol = "GTP"

    def supports(self, session: dict) -> bool:
        protocols = {str(p).upper() for p in session.get("protocols", [])}
        return bool({"GTP", "PFCP"} & protocols)

    def analyze(self, session: dict) -> dict | None:
        msgs = session.get("gtp_msgs", []) + session.get("pfcp_msgs", [])
        if not msgs:
            return None
        failed = [
            m for m in msgs
            if m.get("is_failure")
            or "FAIL" in str(m.get("message", "")).upper()
            or (
                str(m.get("protocol") or "").upper() == "PFCP"
                and str(m.get("cause_code") or m.get("gtpv2.cause_value") or "") not in {"", "1", "REQUEST_ACCEPTED"}
            )
            or (
                str(m.get("protocol") or "").upper() != "PFCP"
                and str(m.get("cause_code") or m.get("gtpv2.cause_value") or "") not in {"", "16", "18", "128", "REQUEST_ACCEPTED"}
            )
        ]
        accepted = [
            m for m in msgs
            if (
                str(m.get("protocol") or "").upper() == "PFCP"
                and str(m.get("cause_code") or m.get("gtpv2.cause_value") or "") in {"1", "REQUEST_ACCEPTED"}
            ) or (
                str(m.get("protocol") or "").upper() != "PFCP"
                and str(m.get("cause_code") or m.get("gtpv2.cause_value") or "") in {"16", "18", "128", "REQUEST_ACCEPTED"}
            )
        ]
        timeout = [m for m in msgs if "TIMEOUT" in str(m.get("message", "")).upper()]
        if timeout:
            return {"agent": "GTP", "label": "CORE_NETWORK_FAILURE", "confidence": 0.88, "evidence": ["Bearer/session control timeout", f"{len(timeout)} timeout indications"]}
        if failed:
            return {"agent": "GTP", "label": "CORE_NETWORK_FAILURE", "confidence": 0.78, "evidence": ["Bearer/session setup failed", f"{len(failed)} failed core-control messages"]}
        if accepted:
            return {"agent": "GTP", "label": "NORMAL_CALL", "confidence": 0.74, "evidence": ["Accepted GTP control-plane responses observed", f"{len(accepted)} successful GTP responses"]}
        return {"agent": "GTP", "label": "NORMAL_CALL", "confidence": 0.4, "evidence": ["No GTP or PFCP failure markers observed"]}
