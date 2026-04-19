"""
RCA Rules Engine — Telecom Grade (v3, Future Ready)

Enhancements:
✔ SIP deep classification
✔ Diameter + Policy awareness
✔ GTP core failures
✔ HTTP/SBI (5G) failures
✔ Transport layer intelligence
✔ Multi-layer correlation
"""

from collections import Counter
from copy import deepcopy

HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
DIAMETER_SUCCESS_CODES = {"2001", "2002"}
RADIUS_ACCEPT_CODES = {"2", "5", "41", "44"}
RADIUS_REJECT_CODES = {"3", "42", "45"}
RADIUS_CHALLENGE_CODES = {"11"}

RCA_METADATA = {
    "CHARGING_FAILURE": {
        "title": "Charging Failure",
        "summary": "The session was rejected by online charging or credit-control signalling before service could proceed.",
        "details": "Charging control failed during credit authorization. This usually points to OCS connectivity issues, subscriber balance policy rejection, or malformed CCR/CCA signaling.",
        "recommendations": [
            "Inspect Diameter CCR/CCA result codes and host reachability.",
            "Verify subscriber charging profile and quota policy.",
            "Check OCS latency, overload, and retransmission patterns.",
        ],
    },
    "SUBSCRIBER_BARRED": {
        "title": "Subscriber Barred",
        "summary": "The subscriber was rejected during authentication or authorization.",
        "details": "Authentication or policy data indicates the subscriber is barred, unauthorized, or provisioned with a restrictive profile.",
        "recommendations": [
            "Validate subscriber status in HSS/UDM/HLR.",
            "Review recent provisioning changes and barring rules.",
            "Confirm roaming and service entitlement configuration.",
        ],
    },
    "POLICY_FAILURE": {
        "title": "Policy Failure",
        "summary": "The session failed because policy control rejected or could not authorize the flow.",
        "details": "Policy decisioning did not allow the requested session setup, often due to PCRF/PCF rules, APN restrictions, or missing subscriber context.",
        "recommendations": [
            "Review PCRF/PCF logs for rejected transactions.",
            "Validate APN/DNN and policy binding configuration.",
            "Inspect subscription profile consistency across control-plane systems.",
        ],
    },
    "NORMAL_CALL": {
        "title": "Normal Session",
        "summary": "The trace shows a normal service establishment and clean teardown pattern.",
        "details": "Signalling completed successfully and the captured exchange does not indicate a service-impacting failure in the correlated session.",
        "recommendations": [
            "Use this session as a baseline reference for healthy behavior.",
        ],
    },
    "USER_BUSY": {
        "title": "User Busy",
        "summary": "The called party was actively busy when the request arrived.",
        "details": "The call/session reached the far end, but the subscriber or endpoint returned a busy condition before acceptance.",
        "recommendations": [
            "Confirm endpoint busy state and concurrent session limits.",
            "Check call waiting and busy-treatment policy for the subscriber.",
        ],
    },
    "USER_REJECTED": {
        "title": "User Rejected",
        "summary": "The called party explicitly rejected the request.",
        "details": "The trace indicates the far end declined the request after signaling was delivered successfully.",
        "recommendations": [
            "Verify user action at the endpoint and handset/UI state.",
            "Review call screening or application-based decline logic.",
        ],
    },
    "SUBSCRIBER_UNREACHABLE": {
        "title": "Subscriber Unreachable",
        "summary": "The target subscriber could not be reached or was unavailable.",
        "details": "The network could not deliver the request to the destination endpoint, typically due to registration absence, radio reachability issues, or inactive state.",
        "recommendations": [
            "Verify registration and last-known reachability state.",
            "Check paging, radio access, or device attach context.",
            "Inspect HLR/HSS/UDM lookup results for routing anomalies.",
        ],
    },
    "ROUTING_FAILURE": {
        "title": "Routing Failure",
        "summary": "The network could not route the request to the intended destination.",
        "details": "Address translation, trunk selection, or network routing logic failed before the session could progress normally.",
        "recommendations": [
            "Validate dialed digits, translation rules, and route tables.",
            "Inspect interconnect routing and trunk availability.",
        ],
    },
    "USER_ABORT": {
        "title": "User Abort",
        "summary": "The originating side canceled the request before completion.",
        "details": "The session was explicitly canceled by the originator after setup had begun, rather than failing due to a network-side timeout.",
        "recommendations": [
            "Correlate with endpoint behavior and UI actions.",
            "Inspect retry/cancel timing for abnormal user-experience patterns.",
        ],
    },
    "NETWORK_REJECTION": {
        "title": "Network Rejection",
        "summary": "The network rejected the request due to signaling or policy validation.",
        "details": "The trace shows a network-side refusal before normal session establishment, which can come from routing, interworking, capability, or policy checks.",
        "recommendations": [
            "Inspect failure response codes and intermediate node behavior.",
            "Review interworking compatibility and policy enforcement points.",
        ],
    },
    "SERVICE_TIMEOUT": {
        "title": "Service Timeout",
        "summary": "The session stalled long enough to hit a service or ringing timeout.",
        "details": "The request progressed partway but no successful completion occurred before a timeout threshold expired.",
        "recommendations": [
            "Check downstream service response time and timer settings.",
            "Inspect announcement, TAS/AS, or application-service dependencies.",
        ],
    },
    "NF_FAILURE": {
        "title": "Network Function Failure",
        "summary": "A 5G service-based function returned an error during the procedure.",
        "details": "HTTP/SBI signaling indicates an NF-side failure, often caused by service overload, misrouting, or invalid context propagation.",
        "recommendations": [
            "Inspect SBI HTTP responses, upstream/downstream retries, and NF health.",
            "Review service discovery, TLS, and authorization context.",
        ],
    },
    "CLIENT_ERROR": {
        "title": "Client Request Error",
        "summary": "The request was rejected because the payload or state was invalid for the target service.",
        "details": "HTTP or protocol semantics indicate the sender submitted an invalid or incomplete request.",
        "recommendations": [
            "Validate request formatting and state machine progression.",
            "Check missing identifiers or stale session context.",
        ],
    },
    "CORE_NETWORK_FAILURE": {
        "title": "Core Network Failure",
        "summary": "Core signaling reported a cause code indicating network-side failure.",
        "details": "The trace contains transport or core-control cause values consistent with gateway, mobility, bearer, or path setup failure.",
        "recommendations": [
            "Inspect core node cause values and peer reachability.",
            "Validate bearer/session setup dependencies end to end.",
        ],
    },
    "NETWORK_CONGESTION": {
        "title": "Transport Congestion",
        "summary": "Retransmissions suggest packet loss, congestion, or unstable transport behavior.",
        "details": "The session includes transport symptoms that commonly accompany congestion, queue drops, or asymmetric packet delivery.",
        "recommendations": [
            "Review TCP retransmission bursts and interface health.",
            "Check latency, packet loss, and firewall/load-balancer behavior.",
        ],
    },
    "TRANSPORT_TIMEOUT": {
        "title": "Transport Timeout",
        "summary": "The transaction timed out at the transport layer.",
        "details": "The signaling exchange did not receive timely responses, suggesting path interruption, firewall blocking, or endpoint inactivity.",
        "recommendations": [
            "Inspect SYN/ACK, reset, and keepalive behavior.",
            "Validate network path continuity and timeout configuration.",
        ],
    },
    "SERVER_ERROR": {
        "title": "Server Error",
        "summary": "The remote service returned a server-side failure indication.",
        "details": "The exchange reached the destination service, but processing failed at the application or control-plane node.",
        "recommendations": [
            "Review server-side logs and overload indicators.",
            "Check recent config changes and backend dependency health.",
        ],
    },
    "DNS_FAILURE": {
        "title": "DNS Resolution Failure",
        "summary": "Name resolution failed or returned an error response during the session.",
        "details": "The trace contains DNS failures such as NXDOMAIN, SERVFAIL, or related resolution errors that can prevent service routing or endpoint reachability.",
        "recommendations": [
            "Inspect DNS query names, response codes, and resolver reachability.",
            "Validate service FQDN configuration and upstream DNS health.",
        ],
    },
    "ICMP_NETWORK_FAILURE": {
        "title": "ICMP Network Failure",
        "summary": "ICMP responses indicate an unreachable path or network-side forwarding problem.",
        "details": "The session includes ICMP error signaling such as destination unreachable or time exceeded, which often points to routing, firewall, or transport path failure.",
        "recommendations": [
            "Review route reachability, firewall policy, and network path symmetry.",
            "Correlate ICMP type and code with transport failures in the same interval.",
        ],
    },
    "NAS_REJECTION": {
        "title": "NAS Registration Rejection",
        "summary": "Standalone NAS signaling indicates registration, mobility, or bearer setup rejection.",
        "details": "NAS-EPS or NAS-5GS messages include reject or cause semantics that suggest the UE was denied registration, service setup, or session continuation by the network.",
        "recommendations": [
            "Inspect NAS message type and cause values across the registration or attach procedure.",
            "Validate subscriber provisioning, security context, and mobility policy.",
        ],
    },
    "UNKNOWN": {
        "title": "Unknown or Incomplete Session",
        "summary": "The trace does not contain enough correlated evidence for a confident RCA classification.",
        "details": "The available packets show partial signaling or insufficient protocol context. More capture depth or additional interfaces may be needed.",
        "recommendations": [
            "Capture adjacent interfaces or extend the trace time window.",
            "Check whether protocol decoding/filtering missed relevant packets.",
        ],
    },
}


# ============================================================
# MAIN CLASSIFIER
# ============================================================

def classify_session(session: dict) -> dict:

    sip_msgs  = session.get("sip_msgs", [])
    dia_msgs  = session.get("dia_msgs", [])
    inap_msgs = session.get("inap_msgs", [])
    gtp_msgs  = session.get("gtp_msgs", [])
    pfcp_msgs = session.get("pfcp_msgs", [])
    http_msgs = session.get("http_msgs", [])
    tcp_msgs  = session.get("tcp_msgs", [])
    dns_msgs  = session.get("dns_msgs", [])
    icmp_msgs = session.get("icmp_msgs", [])
    nas_eps_msgs = session.get("nas_eps_msgs", [])
    nas_5gs_msgs = session.get("nas_5gs_msgs", [])
    radius_msgs = session.get("radius_msgs", [])

    final_code = str(session.get("final_sip_code") or "")

    methods  = {m.get("method") for m in sip_msgs if m.get("method")}
    statuses = {str(m.get("status_code")) for m in sip_msgs if m.get("status_code")}

    has_invite = "INVITE" in methods
    has_bye    = "BYE" in methods
    has_cancel = "CANCEL" in methods
    has_180    = "180" in statuses
    has_183    = "183" in statuses
    has_200    = "200" in statuses

    # ========================================================
    # Diameter signals
    # ========================================================
    charging_failed = any(m.get("is_charging_failure") for m in dia_msgs)
    roaming_denied  = any(m.get("is_roaming_failure") or str(m.get("result_code")) == "5004" for m in dia_msgs)
    auth_failed     = any(
        m.get("is_auth_reject") or m.get("is_auth_failure")
        for m in dia_msgs
    )
    policy_failed   = any(m.get("is_policy_reject") for m in dia_msgs)
    diameter_successes = [m for m in dia_msgs if str(m.get("result_code") or "") in DIAMETER_SUCCESS_CODES]
    diameter_housekeeping = _diameter_housekeeping_profile(session)
    lte_profile = _lte_control_plane_profile(session)

    # ========================================================
    # GTP signals
    # ========================================================
    core_msgs = gtp_msgs + pfcp_msgs
    gtp_failures = [m for m in core_msgs if _gtp_is_failure(m)]
    gtp_successes = [m for m in core_msgs if _gtp_is_success(m)]

    # ========================================================
    # HTTP / SBI signals
    # ========================================================
    http_4xx = any(str(m.get("status_code", "")).startswith("4") for m in http_msgs)
    http_5xx = any(str(m.get("status_code", "")).startswith("5") for m in http_msgs)
    dns_failed = any(m.get("is_failure") for m in dns_msgs)
    benign_icmp_cleanup = _is_benign_icmp_cleanup(session)
    icmp_failed = any(m.get("is_failure") for m in icmp_msgs) and not benign_icmp_cleanup
    nas_failures = [m for m in nas_eps_msgs + nas_5gs_msgs if _nas_is_failure(m)]
    nas_successes = [m for m in nas_eps_msgs + nas_5gs_msgs if _nas_is_success(m)]
    radius_rejects = [m for m in radius_msgs if _radius_is_failure(m)]
    radius_accepts = [m for m in radius_msgs if _radius_is_success(m)]
    radius_challenges = [m for m in radius_msgs if str(m.get("radius_code") or "") in RADIUS_CHALLENGE_CODES]

    # ========================================================
    # TCP signals
    # ========================================================
    retransmissions = any(m.get("retransmission") for m in tcp_msgs)
    timeout = any(m.get("timeout") for m in tcp_msgs)

    # ========================================================
    # R0 — Charging/Auth/Policy (TOP PRIORITY)
    # ========================================================
    if roaming_denied:
        return _result("SUBSCRIBER_BARRED", HIGH, 94,
                       ["Roaming not allowed", "Diameter location update rejected"],
                       "R0_ROAMING_DENIED")

    if auth_failed:
        return _result("SUBSCRIBER_BARRED", HIGH, 90,
                       ["Authentication rejected"],
                       "R0_AUTH")

    if charging_failed:
        return _result("CHARGING_FAILURE", HIGH, 92,
                       ["Diameter charging failure", "CCR rejected"],
                       "R0_CHARGING")

    if policy_failed:
        return _result("POLICY_FAILURE", HIGH, 88,
                       ["Policy control rejected"],
                       "R0_POLICY")
    if radius_rejects:
        evidence = [_radius_failure_evidence(radius_rejects[0])]
        if radius_challenges:
            evidence.append(f"{len(radius_challenges)} Access-Challenge exchange(s) observed before rejection")
        return _result("SUBSCRIBER_BARRED", HIGH, 88, evidence, "R0_RADIUS_REJECT")
    if dia_msgs and diameter_successes and not any(m.get("is_failure") for m in dia_msgs):
        return _result(
            "NORMAL_CALL",
            LOW,
            68,
            [f"{len(diameter_successes)} successful Diameter answers observed", "No Diameter rejection codes present"],
            "R0A_DIAMETER_SUCCESS",
        )
    if diameter_housekeeping["successful_housekeeping"] and not (gtp_failures or nas_failures or icmp_failed):
        return _result(
            "NORMAL_CALL",
            LOW,
            62,
            diameter_housekeeping["evidence"],
            "R0AA_DIAMETER_HOUSEKEEPING",
        )
    if radius_msgs and radius_accepts and not radius_rejects and not (gtp_failures or nas_failures or icmp_failed):
        evidence = [f"{len(radius_accepts)} successful RADIUS response(s) observed", "No RADIUS reject or NAK codes present"]
        if radius_challenges:
            evidence.append(f"{len(radius_challenges)} Access-Challenge exchange(s) observed")
        return _result("NORMAL_CALL", LOW, 66, evidence, "R0AB_RADIUS_SUCCESS")

    if lte_profile["successful_mobility"]:
        return _result(
            "NORMAL_CALL",
            MEDIUM,
            82,
            lte_profile["evidence"],
            "R0B_LTE_MOBILITY_SUCCESS",
        )
    legacy_profile = _legacy_mobility_profile(session)
    if legacy_profile["successful_mobility"]:
        return _result(
            "NORMAL_CALL",
            MEDIUM,
            78,
            legacy_profile["evidence"],
            "R0C_LEGACY_MOBILITY_SUCCESS",
        )
    if benign_icmp_cleanup and gtp_successes:
        return _result(
            "NORMAL_CALL",
            LOW,
            66,
            ["Release Access Bearers cleanup observed", "Port-unreachable ICMP followed bearer release rather than setup failure"],
            "R0D_BENIGN_ICMP_CLEANUP",
        )
    pfcp_info = _pfcp_profile(session)
    if pfcp_info["healthy_session"]:
        return _result(
            "NORMAL_CALL",
            LOW,
            64,
            pfcp_info["evidence"],
            "R0E_PFCP_HEALTHY",
        )

    # ========================================================
    # R1 — Normal Call
    # ========================================================
    if has_200 and has_invite and has_bye:
        return _result("NORMAL_CALL", HIGH, 98,
                       ["200 OK", "BYE observed"],
                       "R1_NORMAL")

    # ========================================================
    # R2 — SIP FAILURE INTELLIGENCE
    # ========================================================

    if final_code == "486":
        return _result("USER_BUSY", HIGH, 95,
                       ["486 Busy Here"],
                       "R2_BUSY")

    if final_code == "603":
        return _result("USER_REJECTED", HIGH, 95,
                       ["603 Decline"],
                       "R2_REJECT")

    if final_code == "480":
        return _result("SUBSCRIBER_UNREACHABLE", HIGH, 90,
                       ["480 Temporarily Unavailable"],
                       "R2_UNREACHABLE")

    if final_code == "404":
        return _result("ROUTING_FAILURE", HIGH, 90,
                       ["404 Not Found"],
                       "R2_ROUTING")

    if final_code == "487":
        if has_cancel:
            return _result("USER_ABORT", HIGH, 90,
                           ["487 due to CANCEL"],
                           "R2_CANCEL")
        elif not has_180:
            return _result("NETWORK_REJECTION", MEDIUM, 75,
                           ["487 early failure"],
                           "R2_487_EARLY")
        else:
            return _result("SERVICE_TIMEOUT", MEDIUM, 70,
                           ["487 after ringing"],
                           "R2_487_TIMEOUT")

    # ========================================================
    # R3 — HTTP / SBI
    # ========================================================
    if http_5xx:
        return _result("NF_FAILURE", HIGH, 90,
                       ["5G NF returned 5xx"],
                       "R3_SBI_5XX")

    if http_4xx:
        return _result("CLIENT_ERROR", MEDIUM, 80,
                       ["Invalid request / UE issue"],
                       "R3_SBI_4XX")

    # ========================================================
    # R3B — DNS / ICMP / NAS
    # ========================================================
    if dns_failed:
        return _result("DNS_FAILURE", MEDIUM, 82,
                       ["DNS resolution error observed"],
                       "R3B_DNS")

    if icmp_failed:
        return _result("ICMP_NETWORK_FAILURE", MEDIUM, 78,
                       ["ICMP unreachable or path error observed"],
                       "R3B_ICMP")

    if nas_failures:
        return _result("NAS_REJECTION", HIGH, 86,
                       ["NAS reject or mobility cause observed"],
                       "R3B_NAS")

    # ========================================================
    # R4 — GTP
    # ========================================================
    if gtp_failures:
        return _result("CORE_NETWORK_FAILURE", HIGH, 85,
                       ["Core-control cause code failure"],
                       "R4_GTP")

    if (gtp_successes or nas_successes) and not (charging_failed or auth_failed or policy_failed):
        return _result("NORMAL_CALL", MEDIUM, 72,
                       ["Successful control-plane procedure responses observed"],
                       "R4B_CONTROL_SUCCESS")

    # ========================================================
    # R5 — Transport
    # ========================================================
    if retransmissions:
        return _result("NETWORK_CONGESTION", MEDIUM, 70,
                       ["TCP retransmissions detected"],
                       "R5_TCP_RETX")

    if timeout:
        return _result("TRANSPORT_TIMEOUT", MEDIUM, 70,
                       ["No response at transport layer"],
                       "R5_TIMEOUT")

    # ========================================================
    # R6 — Generic SIP
    # ========================================================
    if final_code.startswith("5"):
        return _result("SERVER_ERROR", MEDIUM, 80,
                       [f"{final_code} Server Error"],
                       "R6_SERVER")

    if final_code.startswith("4"):
        return _result("NETWORK_REJECTION", MEDIUM, 75,
                       [f"{final_code} Client Failure"],
                       "R6_CLIENT")

    # ========================================================
    # R7 — UNKNOWN
    # ========================================================
    return _result("UNKNOWN", LOW, 30,
                   ["Insufficient signalling"],
                   "R7_UNKNOWN")


def _gtp_is_failure(message: dict) -> bool:
    protocol = str(message.get("protocol") or "").upper()
    cause = str(message.get("cause_code") or message.get("gtpv2.cause_value") or "").strip()
    if not cause:
        return False
    if protocol == "PFCP":
        return cause not in {"1", "REQUEST_ACCEPTED"}
    return cause not in {"16", "18", "128", "REQUEST_ACCEPTED"}


def _gtp_is_success(message: dict) -> bool:
    protocol = str(message.get("protocol") or "").upper()
    cause = str(message.get("cause_code") or message.get("gtpv2.cause_value") or "").strip()
    if protocol == "PFCP":
        return cause in {"1", "REQUEST_ACCEPTED"}
    return cause in {"16", "18", "128", "REQUEST_ACCEPTED"}


def _nas_is_failure(message: dict) -> bool:
    if not message:
        return False
    text = str(message.get("message") or "").upper()
    return any(
        marker in text
        for marker in (
            "ATTACH REJECT",
            "TRACKING AREA UPDATE REJECT",
            "SERVICE REJECT",
            "REGISTRATION REJECT",
            "PDU SESSION ESTABLISHMENT REJECT",
        )
    )


def _nas_is_success(message: dict) -> bool:
    if not message:
        return False
    text = str(message.get("message") or "").upper()
    return any(keyword in text for keyword in ("ACCEPT", "COMPLETE", "REQUEST")) and not _nas_is_failure(message)


def _radius_is_failure(message: dict) -> bool:
    if not message:
        return False
    code = str(message.get("radius_code") or "").strip()
    text = str(message.get("message") or "").upper()
    return code in RADIUS_REJECT_CODES or any(marker in text for marker in ("REJECT", "NAK", "DENIED"))


def _radius_is_success(message: dict) -> bool:
    if not message:
        return False
    code = str(message.get("radius_code") or "").strip()
    return code in RADIUS_ACCEPT_CODES


def _radius_failure_evidence(message: dict) -> str:
    text = str(message.get("message") or "RADIUS reject").strip()
    user = str(message.get("radius_user_name") or message.get("radius_calling_station_id") or "").strip()
    if user:
        return f"{text} for {user}"
    return text


def _legacy_mobility_profile(session: dict) -> dict:
    flow_messages = [str(item.get("message") or "").upper() for item in session.get("flow", [])]
    protocols = {str(protocol).upper() for protocol in session.get("protocols", [])}
    if not protocols & {"MAP", "RANAP", "BSSAP"}:
        return {
            "successful_mobility": False,
            "evidence": ["No legacy mobility signaling observed"],
        }

    has_auth = any("SENDAUTHENTICATIONINFO" in message or "AUTHENTICATION" in message for message in flow_messages)
    has_location_update = any(
        marker in message
        for message in flow_messages
        for marker in ("UPDATEGPRSLOCATION", "UPDATELOCATION", "LOCATION UPDATE")
    )
    has_subscriber_data = any("INSERTSUBSCRIBERDATA" in message for message in flow_messages)
    has_cancel_location = any("CANCELLOCATION" in message for message in flow_messages)
    has_attach_request = any("ATTACH REQUEST" in message for message in flow_messages)
    has_attach_accept = any("ATTACH ACCEPT" in message for message in flow_messages)
    has_attach_complete = any("ATTACH COMPLETE" in message for message in flow_messages)
    has_rau_request = any("ROUTING AREA UPDATE REQUEST" in message for message in flow_messages)
    has_rau_accept = any("ROUTING AREA UPDATE ACCEPT" in message for message in flow_messages)
    has_security_command = any("SECURITYMODECOMMAND" in message for message in flow_messages)
    has_security_complete = any("SECURITYMODECOMPLETE" in message for message in flow_messages)
    has_release_command = any("IU-RELEASECOMMAND" in message for message in flow_messages)
    has_release_complete = any("IU-RELEASECOMPLETE" in message for message in flow_messages)
    result_count = sum(
        1
        for message in flow_messages
        if any(marker in message for marker in (" RESULT", "RETURNRESULT", "ACCEPT", "COMPLETE"))
    )
    explicit_failure = any(
        (
            ("ERROR" in message and "ERRORINDICATION" not in message)
            or any(marker in message for marker in ("REJECT", "FAIL", "ABORT", "REFUSE", "DENIED"))
        )
        for message in flow_messages
    )

    attach_success = (
        has_attach_request
        and has_attach_accept
        and has_attach_complete
        and (has_auth or (has_security_command and has_security_complete))
        and (has_release_command or has_release_complete)
    )
    rau_cleanup = (
        not explicit_failure
        and (
            (has_rau_request and has_security_complete and has_release_complete)
            or (has_rau_accept and has_release_command)
        )
    )
    cancel_location_cleanup = (
        not explicit_failure
        and has_auth
        and has_cancel_location
        and result_count >= 1
    )
    successful_mobility = (
        not explicit_failure
        and (
            attach_success
            or rau_cleanup
            or cancel_location_cleanup
            or (
                has_auth
                and has_location_update
                and (has_subscriber_data or result_count >= 2)
            )
        )
    )

    evidence = []
    if has_auth:
        evidence.append("MAP authentication exchange observed")
    if has_location_update:
        evidence.append("Legacy location update procedure observed")
    if has_subscriber_data:
        evidence.append("Subscriber data insertion observed")
    if has_cancel_location:
        evidence.append("Cancel Location housekeeping observed")
    if attach_success:
        evidence.append("Legacy attach request/accept/complete sequence observed")
    if rau_cleanup:
        evidence.append("Routing Area Update control-plane cleanup slice observed")
    if result_count:
        evidence.append(f"{result_count} successful legacy result messages observed")

    return {
        "successful_mobility": successful_mobility,
        "evidence": evidence or ["Legacy mobility signaling observed"],
    }


def _diameter_housekeeping_profile(session: dict) -> dict:
    dia_msgs = session.get("dia_msgs", [])
    if not dia_msgs:
        return {
            "successful_housekeeping": False,
            "evidence": ["No Diameter signaling observed"],
        }

    protocols = {str(protocol).upper() for protocol in session.get("protocols", [])}
    command_names = {str(msg.get("command_name") or "").upper() for msg in dia_msgs if msg.get("command_name")}
    explicit_failures = any(msg.get("is_failure") for msg in dia_msgs)
    has_clr = "CLR" in command_names or "CANCEL-LOCATION" in command_names
    housekeeping_only = protocols and protocols <= {"DIAMETER", "SCTP"}
    successful_housekeeping = has_clr and housekeeping_only and not explicit_failures

    evidence = []
    if has_clr:
        evidence.append("Diameter Cancel Location housekeeping observed")
    if housekeeping_only:
        evidence.append("Session is limited to Diameter/SCTP mobility cleanup traffic")

    return {
        "successful_housekeeping": successful_housekeeping,
        "evidence": evidence or ["Diameter signaling observed"],
    }


def _is_benign_icmp_cleanup(session: dict) -> bool:
    icmp_msgs = session.get("icmp_msgs", [])
    gtp_msgs = session.get("gtp_msgs", [])
    pfcp_msgs = session.get("pfcp_msgs", [])
    core_msgs = gtp_msgs + pfcp_msgs
    if not icmp_msgs or not core_msgs:
        return False
    if not all(str(msg.get("icmp_type") or "") == "3" and str(msg.get("icmp_code") or "") == "3" for msg in icmp_msgs):
        return False
    if not any(
        marker in str(msg.get("message") or "").upper()
        for msg in core_msgs
        for marker in ("RELEASE ACCESS BEARERS REQUEST", "SESSION DELETION REQUEST")
    ):
        return False
    accepted = sum(1 for msg in core_msgs if _gtp_is_success(msg))
    failures = sum(1 for msg in core_msgs if _gtp_is_failure(msg))
    return accepted >= 1 and failures == 0


def _lte_control_plane_profile(session: dict) -> dict:
    flow = session.get("flow", [])
    flow_messages = [str(item.get("message") or "").upper() for item in flow]
    gtp_msgs = session.get("gtp_msgs", [])
    protocols = {str(protocol).upper() for protocol in session.get("protocols", [])}

    has_handover = any("HANDOVER RESOURCE ALLOCATION" in message for message in flow_messages) and any(
        "HANDOVER NOTIFICATION" in message for message in flow_messages
    )
    has_handover_request = any("HANDOVER REQUEST" in message for message in flow_messages)
    has_status_transfer = any("STATUS TRANSFER" in message for message in flow_messages)
    has_tau = (
        any("TRACKING AREA UPDATE REQUEST" in message for message in flow_messages)
        and any("TRACKING AREA UPDATE ACCEPT" in message for message in flow_messages)
        and any("TRACKING AREA UPDATE COMPLETE" in message for message in flow_messages)
    )
    has_context_release = any("UE CONTEXT RELEASE" in message for message in flow_messages)
    accepted_gtp = sum(1 for message in gtp_msgs if _gtp_is_success(message))
    explicit_reject = any(
        marker in message
        for message in flow_messages
        for marker in (
            "ATTACH REJECT",
            "TRACKING AREA UPDATE REJECT",
            "SERVICE REJECT",
            "REGISTRATION REJECT",
            "PDU SESSION ESTABLISHMENT REJECT",
            "HANDOVER PREPARATION FAILURE",
            "HANDOVER CANCELLED",
            "RADIO-CONNECTION-WITH-UE-LOST",
        )
    )
    control_plane_only = protocols and protocols <= {"SCTP", "S1AP", "NGAP", "NAS_EPS", "NAS_5GS"}
    handover_cleanup = (
        not explicit_reject
        and accepted_gtp == 0
        and control_plane_only
        and has_context_release
        and (has_handover or has_handover_request)
    )

    successful_mobility = (
        not explicit_reject
        and (
            handover_cleanup
            or (
                accepted_gtp >= 2
                and (
                    (has_handover and has_tau)
                    or (has_handover and has_context_release)
                    or (has_tau and has_status_transfer)
                )
            )
        )
    )

    evidence = []
    if has_handover:
        evidence.append("Handover procedure markers observed")
    elif has_handover_request:
        evidence.append("Handover request observed")
    if has_tau:
        evidence.append("Tracking Area Update request/accept/complete observed")
    if has_context_release:
        evidence.append("UE context release observed after procedure progression")
    if accepted_gtp >= 2:
        evidence.append(f"{accepted_gtp} accepted GTP control responses observed")
    if handover_cleanup:
        evidence.append("Inter-RAT handover cleanup slice observed without reject markers")

    return {
        "successful_mobility": successful_mobility,
        "accepted_gtp": accepted_gtp,
        "has_handover": has_handover,
        "has_handover_request": has_handover_request,
        "has_tau": has_tau,
        "has_context_release": has_context_release,
        "has_status_transfer": has_status_transfer,
        "handover_cleanup": handover_cleanup,
        "explicit_reject": explicit_reject,
        "evidence": evidence or ["LTE control-plane procedure markers observed"],
    }


def _pfcp_profile(session: dict) -> dict:
    pfcp_msgs = session.get("pfcp_msgs", [])
    if not pfcp_msgs:
        return {"healthy_session": False, "evidence": ["No PFCP signaling observed"]}

    messages = [str(msg.get("message") or "").upper() for msg in pfcp_msgs]
    failures = sum(1 for msg in pfcp_msgs if _gtp_is_failure(msg) or any(marker in str(msg.get("message") or "").upper() for marker in ("REJECT", "FAIL", "NOT FOUND", "MISSING", "ERROR")))
    has_establishment = any("SESSION ESTABLISHMENT REQUEST" in msg for msg in messages) and any("SESSION ESTABLISHMENT RESPONSE" in msg for msg in messages)
    has_modification = any("SESSION MODIFICATION REQUEST" in msg for msg in messages) and any("SESSION MODIFICATION RESPONSE" in msg for msg in messages)
    has_deletion = any("SESSION DELETION REQUEST" in msg for msg in messages) and any("SESSION DELETION RESPONSE" in msg for msg in messages)
    has_report = any("SESSION REPORT REQUEST" in msg for msg in messages) and any("SESSION REPORT RESPONSE" in msg for msg in messages)
    healthy_session = failures == 0 and has_establishment and (has_modification or has_report or has_deletion)

    evidence = []
    if has_establishment:
        evidence.append("PFCP session establishment request/response observed")
    if has_modification:
        evidence.append("PFCP session modification request/response observed")
    if has_report:
        evidence.append("PFCP session report exchange observed")
    if has_deletion:
        evidence.append("PFCP session deletion request/response observed")

    return {
        "healthy_session": healthy_session,
        "evidence": evidence or ["PFCP signaling observed"],
    }


# ============================================================
# RESULT BUILDER
# ============================================================

def _result(label, severity, confidence, evidence, rule_id):
    meta = RCA_METADATA.get(label, RCA_METADATA["UNKNOWN"])
    return {
        "rca_label": label,
        "rca_title": meta["title"],
        "rca_summary": meta["summary"],
        "rca_detail": meta["details"],
        "severity": severity,
        "confidence_pct": confidence,
        "evidence": evidence,
        "rule_id": rule_id,
        "recommendations": meta["recommendations"],
    }


def blend_hybrid_rca(
    rule_rca: dict,
    pattern_match: dict | None = None,
    anomaly_result: dict | None = None,
    causal_result: dict | None = None,
    agent_result: dict | None = None,
    confidence_result: dict | None = None,
    session: dict | None = None,
) -> dict:
    """
    Blend rule RCA, historical pattern similarity, and anomaly signals.

    The weights favor the rule engine because telecom RCA must remain
    explainable and stable under sparse or noisy learning data.
    """
    rule_rca = deepcopy(rule_rca or _result("UNKNOWN", LOW, 30, ["No rule evidence"], "R0_EMPTY"))
    rule_label = rule_rca.get("rca_label", "UNKNOWN")
    rule_score = min(1.0, max(0.0, float(rule_rca.get("confidence_pct", 0)) / 100.0))
    scores = {rule_label: 0.4 * rule_score}

    pattern_root = None
    pattern_score = 0.0
    if pattern_match:
        pattern_root = pattern_match.get("root_cause")
        historical_success = float(pattern_match.get("historical_success", pattern_match.get("confidence", 0.5)))
        pattern_score = min(1.0, max(0.0, float(pattern_match.get("similarity", 0)) * historical_success))
        if pattern_root:
            scores[pattern_root] = scores.get(pattern_root, 0.0) + (0.25 * pattern_score)

    anomaly_score = 0.0
    anomaly_root = None
    if anomaly_result:
        anomaly_root = anomaly_result.get("suggested_root_cause") or rule_label
        anomaly_score = min(1.0, max(0.0, float(anomaly_result.get("score", 0))))
        if anomaly_result.get("is_anomalous"):
            scores[anomaly_root] = scores.get(anomaly_root, 0.0) + (0.12 * anomaly_score)

    causal_score = 0.0
    causal_root = None
    if causal_result:
        causal_root = causal_result.get("root_cause") or rule_label
        causal_score = min(1.0, max(0.0, float(causal_result.get("causal_strength", causal_result.get("confidence", 0)))))
        scores[causal_root] = scores.get(causal_root, 0.0) + (0.15 * causal_score)

    agent_score = 0.0
    agent_root = None
    if agent_result:
        top_hypothesis = agent_result.get("top_hypothesis") or {}
        agent_root = top_hypothesis.get("label") or rule_label
        agent_score = min(1.0, max(0.0, float(agent_result.get("consensus_score", top_hypothesis.get("confidence", 0)))))
        scores[agent_root] = scores.get(agent_root, 0.0) + (0.08 * agent_score)

    final_label = max(scores.items(), key=lambda item: item[1])[0] if scores else rule_label
    meta = RCA_METADATA.get(final_label, RCA_METADATA["UNKNOWN"])
    confidence_pct = int(round(min(0.99, max(scores.values()) if scores else rule_score) * 100))
    if confidence_result:
        final_label = confidence_result.get("final_label", final_label)
        meta = RCA_METADATA.get(final_label, RCA_METADATA["UNKNOWN"])
        confidence_pct = int(confidence_result.get("confidence_pct", confidence_pct))

    evidence = list(rule_rca.get("evidence", []))
    if pattern_match:
        evidence.append(
            f"Matched historical pattern '{pattern_match.get('scenario', 'Unknown pattern')}' "
            f"with similarity {round(float(pattern_match.get('similarity', 0)) * 100)}%"
        )
    if anomaly_result and anomaly_result.get("is_anomalous"):
        evidence.append(
            f"Anomaly detector flagged session behavior (score {round(float(anomaly_result.get('score', 0)), 2)})"
        )
    if causal_result:
        chain = causal_result.get("causal_chain", [])
        if chain:
            evidence.append(f"Causal inference points to {chain[0].get('event', 'unknown event')}")
    if agent_result and agent_result.get("top_hypothesis"):
        top = agent_result["top_hypothesis"]
        evidence.append(
            f"{top.get('agent', 'Protocol')} agent proposed {top.get('label', 'UNKNOWN')} with {round(float(top.get('confidence', 0)) * 100)}% confidence"
        )

    recommendations = list(meta.get("recommendations", []))

    return {
        "rca_label": final_label,
        "rca_title": meta["title"],
        "rca_summary": meta["summary"],
        "rca_detail": meta["details"],
        "severity": rule_rca.get("severity", meta.get("severity", LOW)),
        "confidence_pct": confidence_pct,
        "evidence": evidence,
        "rule_id": rule_rca.get("rule_id", "R_HYBRID"),
        "recommendations": recommendations,
        "decision_sources": {
            "rule_score": round(rule_score, 4),
            "pattern_score": round(pattern_score, 4),
            "anomaly_score": round(anomaly_score, 4),
            "causal_score": round(causal_score, 4),
            "agent_score": round(agent_score, 4),
            "calibrated_confidence": round(float(confidence_result.get("confidence_score", 0)) if confidence_result else confidence_pct / 100.0, 4),
        },
        "pattern_match": pattern_match,
        "anomaly": anomaly_result,
        "causal_analysis": causal_result,
        "agentic_analysis": agent_result,
        "confidence_model": confidence_result,
        "root_cause": final_label,
        "correlation_confidence": session.get("rca", {}).get("correlation_confidence", 0) if session else 0,
    }


# ============================================================
# BULK APPLY
# ============================================================

def apply_rca(sessions: list) -> list:
    results = []

    for s in sessions:
        rca = classify_session(s)
        s["rca"] = rca   # ✅ FIXED (important for main.py compatibility)
        results.append(s)

    return results


def label_sessions(sessions: list) -> list:
    """Backward-compatible alias used by older pipeline modules."""
    return apply_rca(sessions)


# ============================================================
# SUMMARY
# ============================================================

def summarize_rca(sessions: list) -> dict:
    counter = Counter(s.get("rca", {}).get("rca_label", "UNKNOWN") for s in sessions)

    return {
        "total": len(sessions),
        "distribution": dict(counter)
    }
