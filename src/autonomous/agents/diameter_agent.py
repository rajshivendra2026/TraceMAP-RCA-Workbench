"""Diameter-specific RCA agent."""

from __future__ import annotations

from src.autonomous.agents.base import BaseProtocolAgent


class DiameterAgent(BaseProtocolAgent):
    protocol = "DIAMETER"

    def analyze(self, session: dict) -> dict | None:
        msgs = session.get("dia_msgs", [])
        if not msgs:
            return None
        rejected = [m for m in msgs if m.get("is_failure") or "REJECT" in str(m.get("result_text", "")).upper()]
        charging = [m for m in msgs if m.get("is_charging_failure")]
        auth = [m for m in msgs if m.get("is_auth_failure") or m.get("result_code") in {"5003", 5003}]
        roaming = [m for m in msgs if m.get("is_roaming_failure") or m.get("result_code") in {"5004", 5004}]

        if roaming:
            return self._result("SUBSCRIBER_BARRED", 0.94, ["Diameter roaming denial", f"{len(roaming)} rejected roaming/location-update answers"])
        if auth:
            return self._result("SUBSCRIBER_BARRED", 0.9, ["Diameter authorization rejected", f"{len(auth)} rejected answers"])
        if charging:
            return self._result("CHARGING_FAILURE", 0.86, ["Diameter credit-control rejection", f"{len(charging)} charging failures"])
        if rejected:
            return self._result("POLICY_FAILURE", 0.72, ["Diameter transaction failed", f"{len(rejected)} failed Diameter messages"])
        return self._result("NORMAL_CALL", 0.45, ["Diameter signaling completed without explicit failure"])

    def _result(self, label: str, confidence: float, evidence: list[str]) -> dict:
        return {"agent": "DIAMETER", "label": label, "confidence": confidence, "evidence": evidence}
