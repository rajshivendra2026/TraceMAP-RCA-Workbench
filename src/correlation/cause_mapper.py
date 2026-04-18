"""
Correlation Engine — Cross Layer RCA (v1)

Purpose:
Map SIP symptoms to ROOT CAUSE using Diameter, GTP, HTTP, TCP signals

Output:
Enhances session["rca"] with:
- root_cause
- contributing_factors
- correlation_confidence
"""

def correlate_root_cause(session: dict) -> dict:

    rca = session.get("rca", {})
    evidence = list(rca.get("evidence", []))

    dia_msgs  = session.get("dia_msgs", [])
    gtp_msgs  = session.get("gtp_msgs", [])
    http_msgs = session.get("http_msgs", [])
    tcp_msgs  = session.get("tcp_msgs", [])

    root_cause = None
    factors = []

    # ============================================================
    # DIAMETER CORRELATION (HIGHEST PRIORITY)
    # ============================================================

    for m in dia_msgs:

        if m.get("is_auth_reject") or m.get("is_auth_failure"):
            root_cause = "SUBSCRIBER_BARRED"
            factors.append("Diameter authentication rejected")

        elif m.get("is_failure"):
            root_cause = "CHARGING_FAILURE"
            factors.append("Online charging system rejected CCR")

        elif m.get("is_policy_reject"):
            root_cause = "POLICY_FAILURE"
            factors.append("Policy control rejected session")

    # ============================================================
    # GTP CORRELATION (CORE NETWORK)
    # ============================================================

    for m in gtp_msgs:
        cause = m.get("cause_code")

        if cause and cause != 16:
            root_cause = "CORE_NETWORK_FAILURE"
            factors.append(f"GTP failure cause ({cause})")

    # ============================================================
    # HTTP / SBI (5G)
    # ============================================================

    for m in http_msgs:
        status = str(m.get("status_code", ""))

        if status.startswith("5"):
            root_cause = "NF_FAILURE"
            factors.append("5G NF returned 5xx error")

        elif status.startswith("4"):
            root_cause = "CLIENT_ERROR"
            factors.append("Invalid request or UE issue")

    # ============================================================
    # TRANSPORT LAYER
    # ============================================================

    for m in tcp_msgs:
        if m.get("retransmission"):
            root_cause = "NETWORK_CONGESTION"
            factors.append("TCP retransmissions observed")

        if m.get("timeout"):
            root_cause = "TRANSPORT_TIMEOUT"
            factors.append("Transport layer timeout")

    # ============================================================
    # FINAL DECISION
    # ============================================================

    if root_cause:
        rca["root_cause"] = root_cause
        rca["contributing_factors"] = factors
        rca["correlation_confidence"] = 90

        # 🔥 Upgrade RCA label if needed
        if rca.get("rca_label") == "FAILED_CALL":
            rca["rca_label"] = root_cause

        evidence.extend(factors)
        rca["evidence"] = evidence

    else:
        rca["root_cause"] = rca.get("rca_label")
        rca["correlation_confidence"] = 50

    return session


# ============================================================
# BULK APPLY
# ============================================================

def apply_correlation(sessions: list) -> list:
    results = []

    for s in sessions:
        s = correlate_root_cause(s)
        results.append(s)

    return results
