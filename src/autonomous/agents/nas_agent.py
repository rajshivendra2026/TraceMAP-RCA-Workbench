"""NAS/NGAP/S1AP-specific RCA agent."""

from __future__ import annotations

from src.autonomous.agents.base import BaseProtocolAgent
from src.rules.rca_rules import _legacy_mobility_profile, _lte_control_plane_profile


class NASAgent(BaseProtocolAgent):
    protocol = "NAS_5GS"

    def supports(self, session: dict) -> bool:
        protocols = {str(p).upper() for p in session.get("protocols", [])}
        return bool({"NAS_5GS", "NAS_EPS", "NGAP", "S1AP", "MAP", "RANAP", "BSSAP"} & protocols)

    def analyze(self, session: dict) -> dict | None:
        msgs = (
            session.get("nas_5gs_msgs", [])
            + session.get("nas_eps_msgs", [])
            + session.get("ngap_msgs", [])
            + session.get("s1ap_msgs", [])
        )
        if not msgs:
            return None
        lte_profile = _lte_control_plane_profile(session)
        if lte_profile["successful_mobility"]:
            return {
                "agent": "NAS",
                "label": "NORMAL_CALL",
                "confidence": 0.88,
                "evidence": lte_profile["evidence"],
            }
        legacy_profile = _legacy_mobility_profile(session)
        if legacy_profile["successful_mobility"]:
            return {
                "agent": "NAS",
                "label": "NORMAL_CALL",
                "confidence": 0.82,
                "evidence": legacy_profile["evidence"],
            }
        rejected = [
            m for m in msgs
            if any(
                marker in str(m.get("message", "")).upper()
                for marker in (
                    "ATTACH REJECT",
                    "TRACKING AREA UPDATE REJECT",
                    "SERVICE REJECT",
                    "REGISTRATION REJECT",
                    "PDU SESSION ESTABLISHMENT REJECT",
                )
            )
        ]
        successful = [
            m for m in msgs
            if any(token in str(m.get("message", "")).upper() for token in ("ACCEPT", "COMPLETE"))
        ]
        if rejected:
            return {"agent": "NAS", "label": "NETWORK_REJECTION", "confidence": 0.84, "evidence": ["Mobility/control procedure rejection", f"{len(rejected)} NAS or access-control failures"]}
        if successful:
            return {"agent": "NAS", "label": "NORMAL_CALL", "confidence": 0.7, "evidence": ["Successful NAS/access control completions observed"]}
        return {"agent": "NAS", "label": "NORMAL_CALL", "confidence": 0.42, "evidence": ["No reject causes in NAS/access signaling"]}
