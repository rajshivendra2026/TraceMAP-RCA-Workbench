"""Shared protocol semantics and intelligence overlays.

This layer keeps protocol-specific error/code meaning out of the parser and
RCA rules where possible. Parsers can enrich messages with normalized
semantics, and RCA can then reason over those semantics consistently across
protocol families.
"""

from copy import deepcopy
import re


PROTOCOL_INTELLIGENCE = {
    "DIAMETER": {
        "result_code_map": {
            "2001": {
                "name": "DIAMETER_SUCCESS",
                "semantic_family": "success",
                "description": "The Diameter transaction completed successfully.",
            },
            "2002": {
                "name": "DIAMETER_LIMITED_SUCCESS",
                "semantic_family": "success",
                "description": "The Diameter transaction completed with a limited-success outcome.",
            },
            "4001": {
                "name": "DIAMETER_AUTHENTICATION_REJECTED",
                "semantic_family": "authentication_reject",
                "recommended_rca": "SUBSCRIBER_BARRED",
                "description": "Authentication failed and the subscriber or request was rejected.",
                "recommendations": [
                    "Validate subscriber authentication state in HSS/UDM/HLR.",
                    "Review recent entitlement, barring, or provisioning changes.",
                ],
            },
            "5001": {
                "name": "DIAMETER_ERROR_USER_UNKNOWN",
                "semantic_family": "subscriber_absent",
                "recommended_rca": "SUBSCRIBER_UNREACHABLE",
                "description": "The target user record could not be found for the requested procedure.",
                "recommendations": [
                    "Validate HSS/UDM subscriber data and registration state.",
                    "Check whether the user is provisioned for the queried service or domain.",
                ],
            },
            "5003": {
                "name": "DIAMETER_AUTHORIZATION_REJECTED",
                "semantic_family": "authorization_reject",
                "recommended_rca": "SUBSCRIBER_BARRED",
                "description": "Authorization failed for the requested service or procedure.",
                "recommendations": [
                    "Review subscriber entitlements and barring or policy rules.",
                    "Inspect command-specific authorization handling on the peer node.",
                ],
            },
            "5004": {
                "name": "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
                "semantic_family": "roaming_reject",
                "recommended_rca": "SUBSCRIBER_BARRED",
                "description": "Roaming or location update was rejected for the subscriber.",
                "recommendations": [
                    "Confirm roaming permissions and inter-PLMN configuration.",
                    "Inspect HSS/UDM roaming state and current location records.",
                ],
            },
            "5550": {
                "name": "DIAMETER_ERROR_ABSENT_USER",
                "semantic_family": "subscriber_absent",
                "recommended_rca": "SUBSCRIBER_UNREACHABLE",
                "description": "The subscriber is absent, not currently registered, or not present in the queried service domain.",
                "recommendations": [
                    "Check whether the subscriber is registered in IMS/HSS for the requested service.",
                    "Inspect subscriber reachability, service registration, and network attach state.",
                    "Verify routing or lookup commands are targeting the correct subscriber context.",
                ],
            },
        }
    },
    "RADIUS": {
        "code_map": {
            "2": {"name": "ACCESS_ACCEPT", "semantic_family": "success"},
            "3": {
                "name": "ACCESS_REJECT",
                "semantic_family": "authorization_reject",
                "recommended_rca": "SUBSCRIBER_BARRED",
                "description": "RADIUS rejected the access request.",
            },
            "11": {"name": "ACCESS_CHALLENGE", "semantic_family": "challenge"},
            "42": {
                "name": "COA_NAK",
                "semantic_family": "policy_reject",
                "recommended_rca": "POLICY_FAILURE",
                "description": "The Change-of-Authorization request was negatively acknowledged.",
            },
            "45": {
                "name": "DISCONNECT_NAK",
                "semantic_family": "session_cleanup_failure",
                "recommended_rca": "CORE_NETWORK_FAILURE",
                "description": "The Disconnect request was negatively acknowledged.",
            },
        }
    },
}


def interpret_protocol_message(protocol: str, message: dict) -> dict | None:
    protocol_key = str(protocol or "").upper().strip()
    if not protocol_key or not message:
        return None
    if protocol_key == "DIAMETER":
        return _interpret_diameter(message)
    if protocol_key == "RADIUS":
        return _interpret_radius(message)
    return None


def _interpret_diameter(message: dict) -> dict | None:
    code = _first_non_empty(
        message.get("experimental_result_code"),
        message.get("result_code"),
    )
    if not code:
        return None
    entry = PROTOCOL_INTELLIGENCE["DIAMETER"]["result_code_map"].get(str(code).strip())
    if not entry:
        return None
    intel = deepcopy(entry)
    intel.update(
        {
            "protocol": "DIAMETER",
            "code": str(code).strip(),
            "command_code": _first_non_empty(message.get("command_code"), message.get("cmd_code")),
            "command_name": message.get("command_name"),
            "command_long_name": message.get("command_long_name"),
            "result_source": "experimental_result_code" if message.get("experimental_result_code") else "result_code",
            "evidence": _diameter_evidence(message, entry),
            "confidence": "high",
        }
    )
    return intel


def _interpret_radius(message: dict) -> dict | None:
    code = _first_non_empty(message.get("radius_code"))
    if not code:
        return None
    entry = PROTOCOL_INTELLIGENCE["RADIUS"]["code_map"].get(str(code).strip())
    if not entry:
        return None
    intel = deepcopy(entry)
    intel.update(
        {
            "protocol": "RADIUS",
            "code": str(code).strip(),
            "message_name": message.get("message"),
            "evidence": _radius_evidence(message, entry),
            "confidence": "high",
        }
    )
    return intel


def collect_session_protocol_findings(session: dict) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_collect_diameter_findings(session.get("dia_msgs", [])))
    findings.extend(_collect_radius_findings(session.get("radius_msgs", [])))
    findings.sort(key=lambda item: _finding_priority(item), reverse=True)
    return findings


def build_analyst_brief(session: dict) -> str:
    findings = collect_session_protocol_findings(session)
    if not findings:
        return ""

    top = findings[0]
    supporting = findings[1] if len(findings) > 1 else None
    parts = [
        f"Error identified: {top.get('title')}.",
        f"What this means: {top.get('meaning')}.",
    ]
    if top.get("fault_domain"):
        parts.append(f"Likely fault domain: {top['fault_domain']}.")
    if top.get("network_side") and top.get("not_likely"):
        parts.append(f"This is more likely a network-side issue than {top['not_likely']}.")
    elif top.get("not_likely"):
        parts.append(f"This is less consistent with {top['not_likely']}.")
    if supporting and supporting.get("title") != top.get("title"):
        parts.append(f"Supporting context: {supporting.get('title')} — {supporting.get('meaning')}.")
    next_checks = top.get("recommendations") or []
    if next_checks:
        parts.append(f"Next checks: {'; '.join(next_checks[:3])}.")
    return " ".join(part.strip() for part in parts if part).strip()


def build_protocol_recommendations(session: dict) -> list[str]:
    findings = collect_session_protocol_findings(session)
    if not findings:
        return []
    recommendations: list[str] = []
    for finding in findings:
        for item in finding.get("recommendations", []):
            text = str(item).strip()
            if text and text not in recommendations:
                recommendations.append(text)
    return recommendations[:5]


def _diameter_evidence(message: dict, entry: dict) -> str:
    cmd = message.get("command_name") or message.get("command_long_name") or "Diameter answer"
    return f"{cmd} returned {entry.get('name')} ({_first_non_empty(message.get('experimental_result_code'), message.get('result_code'))})"


def _radius_evidence(message: dict, entry: dict) -> str:
    msg = message.get("message") or "RADIUS"
    return f"{msg} mapped to {entry.get('name')}"


def _collect_diameter_findings(messages: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for message in messages:
        if not message.get("is_failure") and not message.get("effective_result_code"):
            continue
        protocol_intel = message.get("protocol_intelligence") or {}
        if protocol_intel:
            findings.append(
                {
                    "protocol": "DIAMETER",
                    "title": f"{protocol_intel.get('name')} ({protocol_intel.get('code')})",
                    "meaning": protocol_intel.get("description") or "Diameter returned a protocol-defined non-success result.",
                    "fault_domain": _diameter_fault_domain(message, protocol_intel),
                    "not_likely": _diameter_not_likely(message, protocol_intel),
                    "recommendations": list(protocol_intel.get("recommendations", [])),
                    "evidence": protocol_intel.get("evidence"),
                    "network_side": _diameter_answer_from_network(message),
                    "semantic_family": protocol_intel.get("semantic_family"),
                    "score": 100,
                }
            )
            continue

        fallback = _infer_unknown_diameter_finding(message)
        if fallback:
            findings.append(fallback)
    return findings


def _collect_radius_findings(messages: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for message in messages:
        protocol_intel = message.get("protocol_intelligence") or {}
        if not protocol_intel:
            continue
        findings.append(
            {
                "protocol": "RADIUS",
                "title": f"{protocol_intel.get('name')} ({protocol_intel.get('code')})",
                "meaning": protocol_intel.get("description") or "RADIUS returned a policy or authorization outcome.",
                "fault_domain": "AAA policy / subscriber authorization",
                "not_likely": "transport-only noise",
                "recommendations": list(protocol_intel.get("recommendations", [])),
                "evidence": protocol_intel.get("evidence"),
                "network_side": True,
                "semantic_family": protocol_intel.get("semantic_family"),
                "score": 80,
            }
        )
    return findings


def _infer_unknown_diameter_finding(message: dict) -> dict | None:
    code = _first_non_empty(message.get("effective_result_code"), message.get("experimental_result_code"), message.get("result_code"))
    if not code:
        return None

    src_role = _diameter_node_role(message.get("origin_host")) or _diameter_node_role(message.get("src_ip"))
    dst_role = _diameter_node_role(message.get("destination_host")) or _diameter_node_role(message.get("dst_ip"))
    realm_state = _diameter_realm_relationship(message)
    meaning = "A Diameter non-success answer was returned, but the code is not yet mapped in the local protocol registry."
    fault_domain = "Diameter service logic or peer configuration"
    recommendations = [
        "Capture the command code, application ID, and full AVP set for this failure.",
        "Check the responding node's logs for vendor-specific error meaning.",
        "Add the code to the local protocol semantics registry once confirmed.",
    ]

    if realm_state == "cross_plmn":
        meaning = (
            "A Diameter non-success answer was returned across different EPC realms or PLMNs, "
            "which often points to routing, interconnect, roaming, or subscriber-lookup issues."
        )
        fault_domain = "Diameter routing / DSR / interconnect / subscriber lookup"
        recommendations = [
            "Verify Destination-Realm and peer routing for the target PLMN or service domain.",
            "Check DSR or edge-routing policy between the two EPC realms.",
            "Confirm the subscriber is expected to be served across these realms.",
        ]
    elif _diameter_answer_from_network(message):
        meaning = (
            "The failure answer was generated by a network-side control node, which usually means the procedure was rejected during network signalling rather than by the application client."
        )
        fault_domain = f"{src_role or 'Core node'} signalling or subscriber-state handling"
        recommendations = [
            f"Inspect {src_role or 'responding node'} logs for the failed command and AVP set.",
            "Check whether subscriber context, registration state, or routing data was stale or missing.",
            "Correlate with adjacent control-plane procedures to see whether the failure followed attach, paging, or lookup activity.",
        ]

    title = f"Diameter non-success {code}"
    if src_role or dst_role:
        title = f"Diameter non-success {code} between {src_role or 'peer'} and {dst_role or 'peer'}"

    return {
        "protocol": "DIAMETER",
        "title": title,
        "meaning": meaning,
        "fault_domain": fault_domain,
        "not_likely": "a pure handset UI or application-layer issue",
        "recommendations": recommendations,
        "evidence": _build_unknown_diameter_evidence(message),
        "network_side": _diameter_answer_from_network(message),
        "semantic_family": "unknown_non_success",
        "score": 70 if realm_state == "cross_plmn" else 60,
    }


def _build_unknown_diameter_evidence(message: dict) -> str:
    cmd = message.get("command_name") or message.get("command_code") or "Diameter answer"
    code = _first_non_empty(message.get("effective_result_code"), message.get("experimental_result_code"), message.get("result_code")) or "unknown"
    src = message.get("origin_host") or message.get("src_ip") or "unknown source"
    dst = message.get("destination_host") or message.get("dst_ip") or "unknown peer"
    return f"{cmd} returned code {code} from {src} toward {dst}"


def _diameter_fault_domain(message: dict, protocol_intel: dict) -> str:
    family = protocol_intel.get("semantic_family")
    if family == "subscriber_absent":
        return "subscriber state / registration / HSS-IMS data"
    if family in {"authentication_reject", "authorization_reject"}:
        return "subscriber policy / authentication / entitlement control"
    if family == "roaming_reject":
        return "roaming / location-update / inter-PLMN policy"
    return "Diameter signalling / AAA control"


def _diameter_not_likely(message: dict, protocol_intel: dict) -> str:
    family = protocol_intel.get("semantic_family")
    if family == "subscriber_absent":
        return "a transient UI-side issue"
    if family in {"authentication_reject", "authorization_reject", "roaming_reject"}:
        return "a random transport blip"
    return "transport-only noise"


def _diameter_answer_from_network(message: dict) -> bool:
    role = _diameter_node_role(message.get("origin_host")) or _diameter_node_role(message.get("src_ip"))
    return role in {"MME", "AMF", "HSS/HLR", "DSR", "SMSC", "PCRF/PCF", "S-CSCF", "PGW/SMF"}


def _diameter_node_role(value: str | None) -> str | None:
    text = str(value or "").lower()
    if not text:
        return None
    role_markers = (
        ("mme", "MME"),
        ("amf", "AMF"),
        ("hss", "HSS/HLR"),
        ("hlr", "HSS/HLR"),
        ("udm", "HSS/HLR"),
        ("smsc", "SMSC"),
        ("dsr", "DSR"),
        ("pcf", "PCRF/PCF"),
        ("pcrf", "PCRF/PCF"),
        ("ocs", "OCS"),
        ("cscf", "S-CSCF"),
        ("pgw", "PGW/SMF"),
        ("smf", "PGW/SMF"),
        ("sgw", "SGW/UPF"),
        ("upf", "SGW/UPF"),
    )
    for marker, label in role_markers:
        if marker in text:
            return label
    return None


def _diameter_realm_relationship(message: dict) -> str | None:
    origin = _extract_plmn(message.get("origin_realm") or message.get("origin_host"))
    destination = _extract_plmn(message.get("destination_realm") or message.get("destination_host"))
    if not origin or not destination:
        return None
    if origin != destination:
        return "cross_plmn"
    return "same_plmn"


def _extract_plmn(text: str | None) -> str | None:
    value = str(text or "")
    match = re.search(r"mnc(\d{2,3})\.mcc(\d{3})", value, flags=re.IGNORECASE)
    if not match:
        return None
    return f"{match.group(2)}{match.group(1)}"


def _finding_priority(item: dict) -> tuple[int, int]:
    severity_weight = {
        "subscriber_absent": 6,
        "authentication_reject": 5,
        "authorization_reject": 5,
        "roaming_reject": 5,
        "unknown_non_success": 4,
        "policy_reject": 4,
        "session_cleanup_failure": 3,
        "challenge": 1,
        "success": 0,
    }
    family = str(item.get("semantic_family") or "").lower()
    score = int(item.get("score") or 0)
    return (severity_weight.get(family, 2), score)


def _first_non_empty(*values):
    for value in values:
        text = str(value).strip() if value is not None else ""
        if text:
            return text
    return None
