"""Synthetic telecom session generator for controlled RCA training."""

from __future__ import annotations

import random


class SyntheticTraceGenerator:
    """Generates normalized synthetic sessions with injected failures."""

    SCENARIOS = {
        "attach_failure_roaming": {
            "protocols": ["GTP", "DIAMETER", "SCTP"],
            "technologies": ["LTE/4G", "Transport"],
            "flow": ["GTP:Create Session Request", "DIAMETER:CCR-I", "DIAMETER:CCA Failure", "GTP:Session Reject"],
            "rca_label": "CHARGING_FAILURE",
        },
        "dns_resolution_failure": {
            "protocols": ["DNS", "TCP"],
            "technologies": ["Transport"],
            "flow": ["DNS:Query", "DNS:NXDOMAIN"],
            "rca_label": "DNS_FAILURE",
        },
        "nas_registration_reject": {
            "protocols": ["SCTP", "NGAP", "NAS_5GS"],
            "technologies": ["5G", "Transport"],
            "flow": ["NGAP:Initial UE Message", "NAS_5GS:Registration Request", "NAS_5GS:Registration Reject"],
            "rca_label": "NETWORK_REJECTION",
        },
    }

    def generate_session(self, scenario: str, seed: int | None = None, inject_failures: list[str] | None = None) -> dict:
        random.seed(seed)
        template = dict(self.SCENARIOS.get(scenario, self.SCENARIOS["attach_failure_roaming"]))
        flow = []
        base_time = 0.0
        for idx, token in enumerate(template["flow"]):
            protocol, message = token.split(":", 1)
            flow.append(
                {
                    "protocol": protocol,
                    "message": message.strip(),
                    "src": f"NF-{idx}",
                    "dst": f"NF-{idx + 1}",
                    "time": round(base_time + (idx * random.uniform(0.05, 0.25)), 3),
                    "failure": "reject" in message.lower() or "failure" in message.lower(),
                }
            )
        for injected in inject_failures or []:
            flow.append(
                {
                    "protocol": injected.split(":", 1)[0].upper(),
                    "message": injected.split(":", 1)[1],
                    "src": "FAULT-INJECTOR",
                    "dst": "TARGET",
                    "time": round(flow[-1]["time"] + 0.15, 3) if flow else 0.15,
                    "failure": True,
                }
            )
        return {
            "session_id": f"synthetic-{scenario}-{random.randint(1000, 9999)}",
            "call_id": f"syn-{random.randint(1000, 9999)}",
            "protocols": template["protocols"],
            "technologies": template["technologies"],
            "flow": flow,
            "flow_summary": " -> ".join(template["flow"]),
            "rca": {"rca_label": template["rca_label"], "confidence_pct": 70, "evidence": ["Synthetic seed scenario"]},
        }
