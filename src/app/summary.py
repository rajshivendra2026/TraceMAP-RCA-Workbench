from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import re

from src.intelligence.protocol_intelligence import (
    build_analyst_brief,
    build_protocol_recommendations,
    collect_session_protocol_findings,
)


PLMN_NETWORKS = {
    "262001": "Deutsche Telekom Germany",
    "26201": "Deutsche Telekom Germany",
    "262002": "Vodafone Germany",
    "26202": "Vodafone Germany",
    "262003": "O2 Germany",
    "26203": "O2 Germany",
    "262007": "O2 Germany",
    "26207": "O2 Germany",
}

GERMAN_MSISDN_PREFIX_NETWORKS = {
    "151": "Deutsche Telekom Germany",
    "160": "Deutsche Telekom Germany",
    "170": "Deutsche Telekom Germany",
    "171": "Deutsche Telekom Germany",
    "175": "Deutsche Telekom Germany",
    "152": "Vodafone Germany",
    "162": "Vodafone Germany",
    "172": "Vodafone Germany",
    "173": "Vodafone Germany",
    "174": "Vodafone Germany",
    "157": "O2 Germany",
    "163": "O2 Germany",
    "176": "O2 Germany",
    "177": "O2 Germany",
    "178": "O2 Germany",
    "179": "O2 Germany",
}


def build_capture_graph(parsed: dict) -> dict:
    nodes: dict[str, dict] = {}
    edges = []

    def get_node(ip: str) -> dict:
        if ip not in nodes:
            nodes[ip] = {
                "id": ip,
                "label": ip,
                "count": 0,
                "type": classify_node(ip),
            }
        nodes[ip]["count"] += 1
        return nodes[ip]

    for protocol, packets, label_getter in (
        ("SIP", parsed.get("sip", []), lambda p: p.get("method") or p.get("status_code")),
        ("DIAMETER", parsed.get("diameter", []), lambda p: p.get("command_code") or p.get("cmd_code") or "DIAMETER"),
        ("INAP", parsed.get("inap", []), lambda p: p.get("inap_op_name") or p.get("inap_opcode") or "INAP"),
        ("GTP", parsed.get("gtp", []), lambda p: p.get("gtpv2.message_type") or p.get("gtp.message_type") or "GTP"),
        ("RADIUS", parsed.get("radius", []), lambda p: p.get("message") or "RADIUS"),
        ("S1AP", parsed.get("s1ap", []), lambda p: p.get("message") or "S1AP"),
        ("NGAP", parsed.get("ngap", []), lambda p: p.get("message") or "NGAP"),
        ("RANAP", parsed.get("ranap", []), lambda p: p.get("message") or "RANAP"),
        ("BSSAP", parsed.get("bssap", []), lambda p: p.get("message") or "BSSAP"),
        ("MAP", parsed.get("map", []), lambda p: p.get("message") or "MAP"),
        ("HTTP", parsed.get("http", []), lambda p: p.get("message") or "HTTP"),
        ("DNS", parsed.get("dns", []), lambda p: p.get("message") or "DNS"),
        ("ICMP", parsed.get("icmp", []), lambda p: p.get("message") or "ICMP"),
        ("NAS_EPS", parsed.get("nas_eps", []), lambda p: p.get("message") or "NAS_EPS"),
        ("NAS_5GS", parsed.get("nas_5gs", []), lambda p: p.get("message") or "NAS_5GS"),
        ("TCP", parsed.get("tcp", []), lambda p: p.get("message") or "TCP"),
        ("UDP", parsed.get("udp", []), lambda p: p.get("message") or "UDP"),
        ("PFCP", parsed.get("pfcp", []), lambda p: p.get("message") or "PFCP"),
        ("SCTP", parsed.get("sctp", []), lambda p: p.get("message") or "SCTP"),
    ):
        for pkt in packets:
            src = pkt.get("src_ip")
            dst = pkt.get("dst_ip")
            if not src or not dst:
                continue
            get_node(src)
            get_node(dst)
            edges.append(
                {
                    "source": src,
                    "target": dst,
                    "protocol": protocol,
                    "label": label_getter(pkt),
                }
            )

    return {"nodes": list(nodes.values()), "edges": edges}


def build_session_graph(flow: list) -> dict:
    nodes: dict[str, dict] = {}
    edges = []

    def get_node(node_label: str) -> dict:
        if node_label not in nodes:
            parts = str(node_label).split("\n", 1)
            nodes[node_label] = {
                "id": node_label,
                "label": parts[-1] if parts else node_label,
                "count": 0,
                "type": parts[0] if len(parts) > 1 else "NODE",
            }
        nodes[node_label]["count"] += 1
        return nodes[node_label]

    for item in flow:
        src = item.get("src")
        dst = item.get("dst")
        if not src or not dst:
            continue
        get_node(src)
        get_node(dst)
        edges.append(
            {
                "source": src,
                "target": dst,
                "protocol": item.get("protocol"),
                "label": item.get("message"),
                "time": item.get("time"),
            }
        )

    return {"nodes": list(nodes.values()), "edges": edges}


def classify_node(ip: str) -> str:
    if not ip:
        return "UNKNOWN"
    if ip.startswith("192.168"):
        return "UE"
    if ip.startswith("10."):
        return "CORE"
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) > 1:
            try:
                second_octet = int(parts[1])
            except ValueError:
                second_octet = -1
            if 16 <= second_octet <= 31:
                return "IMS"
    return "EXTERNAL"


def session_summary(session: dict) -> dict:
    rca = session.get("hybrid_rca") or session.get("rca", {})
    autonomous = session.get("autonomous_rca") or {}
    protocol_findings = collect_session_protocol_findings(session)
    analyst_brief = build_analyst_brief(session)
    protocol_recommendations = build_protocol_recommendations(session)
    recommendations = protocol_recommendations or rca.get("recommendations", [])
    details_summary = build_session_details_summary(session)
    failure_topology = _build_failure_topology(
        session,
        node_inventory=details_summary.get("node_inventory", []),
    )
    packet_count = sum(
        len(value)
        for key, value in session.items()
        if key.endswith("_msgs") and isinstance(value, list)
    )
    return {
        "call_id": session.get("call_id"),
        "flow": session.get("flow", []),
        "graph": build_session_graph(session.get("flow", [])),
        "causal_graph": autonomous.get("session_causal_graph"),
        "flow_summary": session.get("flow_summary", ""),
        "final_sip_code": session.get("final_sip_code", ""),
        "dia_correlation": session.get("dia_correlation", ""),
        "gtp_correlation": session.get("gtp_correlation", ""),
        "correlation_summary": _build_correlation_summary(session),
        "correlation_methods": session.get("correlation_methods", []),
        "correlation_evidence": session.get("correlation_evidence", []),
        "imsi": session.get("imsi"),
        "msisdn": session.get("msisdn"),
        "subscriber_ip": session.get("subscriber_ip"),
        "duration_ms": session.get("duration_ms", 0),
        "packet_count": packet_count,
        "protocols": session.get("protocols", []),
        "technologies": session.get("technologies", []),
        "rca_label": rca.get("rca_label", "UNKNOWN"),
        "rca_title": rca.get("rca_title", rca.get("rca_label", "Unknown")),
        "rca_summary": rca.get("rca_summary", ""),
        "rca_detail": rca.get("rca_detail", ""),
        "analyst_brief": analyst_brief,
        "protocol_findings": protocol_findings,
        "confidence": rca.get("confidence_pct", 0),
        "raw_confidence": rca.get("raw_confidence_pct", rca.get("confidence_pct", 0)),
        "confidence_band": rca.get("confidence_band", ""),
        "calibration_source": rca.get("calibration_source", "uncalibrated"),
        "severity": rca.get("severity", ""),
        "rule_id": rca.get("rule_id", ""),
        "priority_score": rca.get("priority_score", session.get("priority_score", 0)),
        "priority_band": rca.get("priority_band", session.get("priority_band", "low")),
        "priority_reason": rca.get("priority_reason", session.get("priority_reason", "baseline inspection")),
        "evidence": rca.get("evidence", []),
        "recommendations": recommendations,
        "decision_sources": rca.get("decision_sources", {}),
        "llm_explanation": rca.get("llm_explanation", ""),
        "pattern_match": rca.get("pattern_match"),
        "anomaly": rca.get("anomaly"),
        "causal_analysis": rca.get("causal_analysis") or autonomous.get("causal_analysis"),
        "agentic_analysis": rca.get("agentic_analysis") or autonomous.get("agentic_analysis"),
        "confidence_model": rca.get("confidence_model") or autonomous.get("confidence_model"),
        "knowledge_graph_summary": rca.get("knowledge_graph_summary") or autonomous.get("knowledge_graph_summary"),
        "timeseries_summary": rca.get("timeseries_summary") or autonomous.get("timeseries_summary"),
        "details_summary": details_summary,
        "failure_topology": failure_topology,
        "root_cause": rca.get("root_cause"),
        "contributing_factors": rca.get("contributing_factors", []),
        "correlation_confidence": rca.get("correlation_confidence", 0),
    }


def _build_correlation_summary(session: dict) -> str:
    parts = []

    dia = session.get("dia_correlation")
    if dia and dia not in {"none", "unmatched"}:
        parts.append(f"Dia {dia}")

    gtp = session.get("gtp_correlation")
    if gtp and gtp not in {"none", "unmatched"}:
        parts.append(f"GTP {gtp}")

    methods = set(session.get("correlation_methods", []) or [])
    if "state:teid_continuation" in methods:
        parts.append("State TEID chain")
    if "state:access_subscriber_bridge" in methods:
        parts.append("State access bridge")

    subscriber_ip = session.get("subscriber_ip") or next(
        (
            message.get("framed_ip")
            for message in session.get("dia_msgs", [])
            if message.get("framed_ip")
        ),
        None,
    ) or next(
        (
            message.get("gtp.subscriber_ip")
            for message in session.get("gtp_msgs", [])
            if message.get("gtp.subscriber_ip")
        ),
        None,
    )
    if subscriber_ip:
        parts.append(f"UE IP {subscriber_ip}")

    imsi = session.get("imsi") or next(
        (
            message.get("gtpv2.imsi")
            for message in session.get("gtp_msgs", [])
            if message.get("gtpv2.imsi")
        ),
        None,
    )
    if imsi:
        parts.append(f"IMSI {imsi}")

    teid = next(
        (
            message.get("gtp.teid") or message.get("gtp.f_teid") or message.get("gtp.tid")
            for message in session.get("gtp_msgs", [])
            if message.get("gtp.teid") or message.get("gtp.f_teid") or message.get("gtp.tid")
        ),
        None,
    )
    if teid:
        parts.append(f"TEID {teid}")

    return " · ".join(parts[:5]) or dia or gtp or "No correlation"


def build_capture_summary(parsed: dict, sessions: list, capture_meta: dict | None = None) -> dict:
    capture_meta = capture_meta or {}
    technology_counts = {
        "2G": len(parsed.get("bssap", [])),
        "3G": len(parsed.get("ranap", [])) + len(parsed.get("map", [])),
        "LTE/4G": len(parsed.get("s1ap", [])) + len(parsed.get("gtp", [])) + len(parsed.get("nas_eps", [])),
        "5G": len(parsed.get("ngap", [])) + len(parsed.get("pfcp", [])) + len(parsed.get("http", [])) + len(parsed.get("nas_5gs", [])),
        "IMS": len(parsed.get("sip", [])) + len(parsed.get("diameter", [])) + len(parsed.get("inap", [])),
        "AAA": len(parsed.get("radius", [])),
        "Transport": len(parsed.get("tcp", [])) + len(parsed.get("udp", [])) + len(parsed.get("sctp", [])),
        "SCTP": len(parsed.get("sctp", [])),
        "Core Services": len(parsed.get("dns", [])) + len(parsed.get("icmp", [])),
        "HTTPS": len([p for p in parsed.get("http", []) if p.get("tls_type")]),
    }
    protocol_counts = {
        key.upper(): len(value)
        for key, value in parsed.items()
        if isinstance(value, list) and value
    }
    protocol_breakdown = _build_protocol_breakdown(parsed)
    tcp_issues = len(_collect_tcp_transport_issues(parsed))
    http_transactions = len(parsed.get("http", []))
    ims_sessions = sum(1 for s in sessions if "IMS" in s.get("technologies", []))
    top_protocol = max(protocol_counts.items(), key=lambda item: item[1])[0] if protocol_counts else "-"
    successful_sessions = sum(
        1 for s in sessions
        if (s.get("hybrid_rca") or s.get("rca", {})).get("rca_label") == "NORMAL_CALL"
    )
    failed_sessions = max(0, len(sessions) - successful_sessions)
    avg_duration_ms = (
        sum(float(s.get("duration_ms") or 0) for s in sessions) / len(sessions)
        if sessions else 0
    )
    total_packets = sum(len(value) for value in parsed.values() if isinstance(value, list))
    rca_distribution = Counter(
        (s.get("hybrid_rca") or s.get("rca", {})).get("rca_label", "UNKNOWN")
        for s in sessions
    )
    top_rca = rca_distribution.most_common(1)[0][0] if rca_distribution else "-"
    endpoint_activity = _build_endpoint_activity(parsed)
    capture_window = _capture_window(parsed)
    expert_findings = _build_expert_findings(
        protocol_counts=protocol_counts,
        technology_counts=technology_counts,
        tcp_issues=tcp_issues,
        failed_sessions=failed_sessions,
        sessions=sessions,
    )
    details = build_trace_details_summary(
        parsed,
        sessions,
        protocol_counts,
        technology_counts,
        protocol_breakdown=protocol_breakdown,
        capture_window=capture_window,
        capture_meta=capture_meta,
    )

    return {
        "technology_counts": technology_counts,
        "protocol_counts": protocol_counts,
        "protocol_breakdown": protocol_breakdown,
        "rca_distribution": dict(rca_distribution),
        "top_endpoints": endpoint_activity[:6],
        "expert_findings": expert_findings,
        "details": details,
        "error_analysis": _build_error_analysis(parsed, sessions, capture_window, details),
        "failure_topology": _build_capture_failure_topology(sessions, details),
        "kpis": {
            "total_sessions": len(sessions),
            "total_packets": capture_window["total_frames"] or total_packets,
            "technologies_seen": sum(1 for _, count in technology_counts.items() if count > 0),
            "protocols_seen": len(protocol_counts),
            "ims_sessions": ims_sessions,
            "radio_2g_3g": technology_counts["2G"] + technology_counts["3G"],
            "radio_4g": technology_counts["LTE/4G"],
            "radio_5g": technology_counts["5G"],
            "tcp_issues": tcp_issues,
            "http_https_messages": http_transactions,
            "sctp_messages": technology_counts["SCTP"],
            "failed_sessions": failed_sessions,
            "successful_sessions": successful_sessions,
            "avg_duration_ms": round(avg_duration_ms, 1),
            "top_rca": top_rca,
            "top_protocol": top_protocol,
        },
    }


def _build_error_analysis(parsed: dict, sessions: list, capture_window: dict, details: dict) -> dict:
    sip_401_packets = [p for p in parsed.get("sip", []) if str(p.get("status_code")) == "401"]
    tcp_issue_packets = _collect_tcp_transport_issues(parsed)
    tcp_issue_breakdown = _tcp_issue_breakdown(tcp_issue_packets)
    tcp_resets = [p for p in parsed.get("tcp", []) if p.get("reset") is True or "RST" in str(p.get("message", "")).upper()]
    gtp_context_not_found = [
        p for p in parsed.get("gtp", [])
        if str(p.get("cause_code")) == "64" or "CONTEXT NOT FOUND" in str(p.get("message", "")).upper()
    ]
    ngap_release = [
        p for p in parsed.get("ngap", [])
        if "UE CONTEXT RELEASE" in str(p.get("message", "")).upper() or str(p.get("procedure")) in {"41", "42"}
    ]
    s1ap_release = [
        p for p in parsed.get("s1ap", [])
        if "UE CONTEXT RELEASE" in str(p.get("message", "")).upper() or str(p.get("procedure")) in {"18"}
    ]
    diameter_non_success = [
        p for p in parsed.get("diameter", [])
        if p.get("is_failure") and str(p.get("result_code")) not in {"1001"}
    ]
    diameter_semantic_counts = Counter(
        p.get("semantic_label") or p.get("result_text") or str(p.get("effective_result_code") or p.get("result_code") or "")
        for p in diameter_non_success
    )
    dominant_diameter_issue = diameter_semantic_counts.most_common(1)[0][0] if diameter_semantic_counts else None
    diameter_notable = [
        p for p in parsed.get("diameter", [])
        if p.get("is_failure") and str(p.get("result_code")) in {"1001"}
    ]
    radius_failures = [
        p for p in parsed.get("radius", [])
        if p.get("is_failure") or str(p.get("radius_code") or "") in {"3", "42", "45"}
    ]
    radius_challenges = [
        p for p in parsed.get("radius", [])
        if str(p.get("radius_code") or "") == "11"
    ]

    categories = [
        _error_category("SIP 401 Unauthorized", len(sip_401_packets), "none", "Normal IMS AKA authentication flow"),
        _error_category("TCP Transport Issues", len(tcp_issue_packets), "low" if len(tcp_issue_packets) < 80 else "medium", _describe_tcp_issue_breakdown(tcp_issue_breakdown)),
        _error_category("GTPv2 Context Not Found", len(gtp_context_not_found), "medium" if gtp_context_not_found else "none", "Bearer deletion or session cleanup issue"),
        _error_category("NGAP UE Context Release", len(ngap_release), "none", "Normal 5G mobility or idle-mode control"),
        _error_category("S1AP UE Context Release", len(s1ap_release), "none", "Normal 4G mobility or context management"),
        _error_category(
            "Diameter Errors",
            len(diameter_non_success),
            "none" if not diameter_non_success else "medium",
            dominant_diameter_issue or "AAA or policy transaction issue",
        ),
        _error_category("Diameter Informational Non-Success", len(diameter_notable), "low" if diameter_notable else "none", "Reviewable but not necessarily a service failure"),
        _error_category("RADIUS Errors", len(radius_failures), "none" if not radius_failures else "medium", "Access control or accounting reject / NAK"),
        _error_category("TCP RST", len(tcp_resets), "none" if not tcp_resets else "medium", "Abrupt transport termination"),
    ]

    sections = []
    if sip_401_packets:
        sections.append(
            {
                "title": "SIP — 401 Unauthorized",
                "severity": "none",
                "verdict": "Expected behavior",
                "analysis": "401 responses are treated as normal IMS AKA challenge behavior when registration later succeeds with 200 OK responses.",
                "examples": _packet_examples(sip_401_packets, fields=("frame_number", "time_label", "message", "src_ip", "dst_ip")),
            }
        )
    if tcp_issue_packets:
        sections.append(
            {
                "title": "TCP Transport Issues",
                "severity": "low" if len(tcp_issue_packets) < 80 else "medium",
                "verdict": "Transport noise / packet loss indicator",
                "analysis": (
                    f"Detected {len(tcp_issue_packets)} transport-analysis marker(s): "
                    f"{_describe_tcp_issue_breakdown(tcp_issue_breakdown, include_counts=True)}. "
                    "These usually reflect packet loss, missing ACKs, incomplete visibility in multi-point captures, or transient tunnel-path instability."
                ),
                "examples": _packet_examples(tcp_issue_packets, fields=("frame_number", "time_label", "src_ip", "dst_ip", "message", "issue_type")),
            }
        )
    if gtp_context_not_found:
        sections.append(
            {
                "title": "GTPv2 — Context Not Found",
                "severity": "medium",
                "verdict": "Genuine session cleanup issue",
                "analysis": "Context Not Found on GTPv2 control traffic usually means bearer or session state was already removed on one side before cleanup completed on the peer.",
                "examples": _packet_examples(gtp_context_not_found, fields=("frame_number", "time_label", "src_ip", "dst_ip", "message", "cause_code")),
            }
        )
    if ngap_release:
        sections.append(
            {
                "title": "NGAP — UE Context Release",
                "severity": "none",
                "verdict": "Expected control-plane behavior",
                "analysis": "These events normally appear during idle-mode transitions, release of radio resources, or mobility cleanup on the 5G side.",
                "examples": _packet_examples(ngap_release, fields=("frame_number", "time_label", "message", "src_ip", "dst_ip")),
            }
        )
    if s1ap_release:
        sections.append(
            {
                "title": "S1AP — UE Context Release",
                "severity": "none",
                "verdict": "Expected control-plane behavior",
                "analysis": "These events usually reflect LTE-side context cleanup, detach handling, or inter-RAT mobility transitions.",
                "examples": _packet_examples(s1ap_release, fields=("frame_number", "time_label", "message", "src_ip", "dst_ip")),
            }
        )
    if radius_failures or radius_challenges:
        sections.append(
            {
                "title": "RADIUS — AAA Control",
                "severity": "medium" if radius_failures else "none",
                "verdict": "Reviewable AAA exchange" if radius_failures else "Expected challenge / authorization flow",
                "analysis": (
                    f"Observed {len(radius_failures)} reject-or-NAK RADIUS event(s)"
                    f"{' and ' if radius_failures and radius_challenges else ''}"
                    f"{len(radius_challenges)} challenge event(s)." if radius_failures or radius_challenges else ""
                ),
                "examples": _packet_examples(radius_failures or radius_challenges, fields=("frame_number", "time_label", "message", "src_ip", "dst_ip", "radius_user_name")),
            }
        )
    if diameter_non_success:
        sections.append(
            {
                "title": f"Diameter — {dominant_diameter_issue or 'Non-success responses'}",
                "severity": "medium",
                "verdict": "Protocol-semantic review required",
                "analysis": (
                    f"Observed {len(diameter_non_success)} non-success Diameter response(s). "
                    f"The dominant semantic finding is {dominant_diameter_issue or 'an unspecified non-success response'}, "
                    "which should drive RCA before falling back to generic policy or charging buckets."
                ),
                "examples": _packet_examples(
                    diameter_non_success,
                    fields=("frame_number", "time_label", "command_name", "effective_result_code", "semantic_label", "src_ip", "dst_ip"),
                ),
            }
        )

    timeline = _build_error_timeline(sip_401_packets, parsed.get("sip", []), gtp_context_not_found, ngap_release, s1ap_release)
    recommendations = _build_error_recommendations(gtp_context_not_found, tcp_issue_packets, diameter_non_success)
    assessment = _build_error_assessment(gtp_context_not_found, tcp_issue_packets, diameter_non_success, details)

    return {
        "headline": "Protocol error and expected-behavior analysis",
        "categories": categories,
        "sections": sections,
        "timeline": timeline,
        "recommendations": recommendations,
        "assessment": assessment,
    }


def _build_endpoint_activity(parsed: dict) -> list:
    activity = Counter()
    for packets in parsed.values():
        if not isinstance(packets, list):
            continue
        for packet in packets:
            src = packet.get("src_ip")
            dst = packet.get("dst_ip")
            if src:
                activity[src] += 1
            if dst:
                activity[dst] += 1
    return [
        {"endpoint": endpoint, "count": count}
        for endpoint, count in activity.most_common(10)
    ]


def _build_expert_findings(protocol_counts: dict, technology_counts: dict, tcp_issues: int, failed_sessions: int, sessions: list) -> list:
    findings = []
    labels = Counter()
    abnormal_sessions = []
    unknown_sessions = []

    for session in sessions:
        final_rca = session.get("hybrid_rca") or session.get("rca", {})
        label = final_rca.get("rca_label", "UNKNOWN")
        labels[label] += 1
        if label == "UNKNOWN":
            unknown_sessions.append((session, final_rca))
        elif label != "NORMAL_CALL":
            abnormal_sessions.append((session, final_rca))

    total_sessions = len(sessions) or 1
    abnormal_count = len(abnormal_sessions)
    unknown_count = len(unknown_sessions)
    abnormal_ratio = abnormal_count / total_sessions
    unknown_ratio = unknown_count / total_sessions

    if abnormal_count:
        top_label, top_count = Counter(
            final_rca.get("rca_label", "UNKNOWN")
            for _, final_rca in abnormal_sessions
        ).most_common(1)[0]
        severity = "error" if abnormal_ratio >= 0.45 or top_label in {"SUBSCRIBER_BARRED", "NETWORK_REJECTION", "CHARGING_FAILURE", "CORE_NETWORK_FAILURE"} else "warn"
        findings.append({
            "severity": severity,
            "title": f"{top_label.replace('_', ' ').title()} is the dominant abnormal pattern",
            "body": f"{abnormal_count} of {len(sessions)} correlated sessions are non-normal, and {top_count} of them converge on {top_label.replace('_', ' ').title()}. Start with the highest-confidence abnormal session in the explorer.",
        })

        lead_session, lead_rca = max(
            abnormal_sessions,
            key=lambda item: (
                float(item[0].get("priority_score", 0) or (item[1] or {}).get("priority_score", 0)),
                float((item[1] or {}).get("confidence_pct", 0)),
            )
        )
        lead_title = lead_rca.get("rca_title") or lead_rca.get("rca_label", "Unknown")
        lead_confidence = int(round(float(lead_rca.get("confidence_pct", 0))))
        lead_evidence = list(lead_rca.get("evidence", []))[:2]
        lead_hint = "; ".join(str(item) for item in lead_evidence) if lead_evidence else "Review RCA evidence and ladder flow for the first failure marker."
        findings.append({
            "severity": "note",
            "title": f"Lead investigation target: {lead_title}",
            "body": f"The strongest abnormal session is ranked at priority {int(round(float(lead_session.get('priority_score', lead_rca.get('priority_score', 0)) or 0)))} and classified at {lead_confidence}% confidence. Key evidence: {lead_hint}",
        })

    if unknown_count:
        severity = "warn" if unknown_ratio >= 0.3 else "note"
        findings.append({
            "severity": severity,
            "title": "Unknown or weakly stitched sessions remain",
            "body": f"{unknown_count} session(s) are still classified as UNKNOWN. This usually points to sparse signaling, partial decode coverage, or control-plane fragments that need closer correlation review.",
        })

    if tcp_issues > 50:
        findings.append({
            "severity": "warn",
            "title": "High transport instability",
            "body": f"Observed {tcp_issues} TCP anomalies, which is high for a single capture and may indicate congestion, resets, or packet loss.",
        })
    elif tcp_issues > 0:
        findings.append({
            "severity": "note",
            "title": "Transport noise is present",
            "body": f"{tcp_issues} TCP anomaly marker(s) were observed. That may affect session quality or explain retransmission-heavy flows without being the primary RCA.",
        })

    if protocol_counts.get("DIAMETER", 0) and labels.get("CHARGING_FAILURE", 0):
        findings.append({
            "severity": "error",
            "title": "Charging control path is failing",
            "body": f"Diameter signaling is present and {labels.get('CHARGING_FAILURE', 0)} session(s) were classified as charging failures. Review credit-control and policy exchanges first.",
        })

    if protocol_counts.get("SCTP", 0) and (protocol_counts.get("S1AP", 0) or protocol_counts.get("NGAP", 0)):
        findings.append({
            "severity": "note",
            "title": "Strong control-plane visibility",
            "body": "SCTP plus access signaling is present, which gives good visibility into telecom procedure progression and makes ladder-view inspection more reliable.",
        })

    if technology_counts.get("5G", 0) and protocol_counts.get("HTTP", 0) == 0 and protocol_counts.get("PFCP", 0) == 0:
        findings.append({
            "severity": "note",
            "title": "Partial 5G visibility",
            "body": "5G access signaling is present, but service-based or user-plane control traffic is limited in this capture.",
        })

    active_technologies = [tech for tech, count in technology_counts.items() if count > 0]
    if len(active_technologies) >= 3:
        findings.append({
            "severity": "chat",
            "title": "Multi-domain trace with cross-layer context",
            "body": f"This capture spans {', '.join(active_technologies[:4])}. Use the protocol intelligence and session RCA panels together because multiple technology domains are contributing context.",
        })

    if not findings:
        top_protocol = max(protocol_counts.items(), key=lambda item: item[1])[0] if protocol_counts else "UNKNOWN"
        findings.append({
            "severity": "chat",
            "title": "Capture looks broadly healthy",
            "body": f"No elevated anomalies surfaced at summary level. Start with the dominant {top_protocol} conversations and use the session explorer to inspect a representative normal session.",
        })

    severity_rank = {"error": 0, "warn": 1, "note": 2, "chat": 3}
    deduped = []
    seen_titles = set()
    for finding in sorted(findings, key=lambda item: (severity_rank.get(item.get("severity", "chat"), 9), item.get("title", ""))):
        title = finding.get("title", "")
        if title in seen_titles:
            continue
        seen_titles.add(title)
        deduped.append(finding)
    return deduped[:4]


def build_trace_details_summary(
    parsed: dict,
    sessions: list,
    protocol_counts: dict,
    technology_counts: dict,
    *,
    protocol_breakdown: list | None = None,
    capture_window: dict | None = None,
    capture_meta: dict | None = None,
) -> dict:
    protocol_breakdown = protocol_breakdown or _build_protocol_breakdown(parsed)
    capture_window = capture_window or _capture_window(parsed)
    capture_meta = capture_meta or {}
    subscriber = _extract_primary_subscriber(parsed, sessions)
    a_party, b_party = _extract_trace_parties(parsed, sessions, subscriber=subscriber)
    top_protocols = sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)[:4]
    technologies_seen = [tech for tech, count in technology_counts.items() if count > 0]
    dominant_protocol = _infer_dominant_protocol(protocol_breakdown, top_protocols)
    trace_type = _infer_trace_type(protocol_counts, technologies_seen, protocol_breakdown)
    scenario = _infer_test_scenario(protocol_counts, technologies_seen)
    headline = _build_trace_headline(trace_type, top_protocols, technologies_seen)
    observations = _build_key_observations(
        protocol_counts=protocol_counts,
        technology_counts=technology_counts,
        protocol_breakdown=protocol_breakdown,
        sessions=sessions,
    )
    party_identities = _build_party_identities(parsed, sessions, subscriber, a_party, b_party)
    node_inventory = _build_node_inventory(parsed, protocol_counts)
    topology = _build_topology_inference(parsed, protocol_counts, subscriber, a_party, b_party)
    file_name = capture_meta.get("filename")
    file_size_bytes = int(capture_meta.get("size_bytes", 0) or 0)
    overview = [
        ("File", file_name or "Current upload"),
        ("Capture Duration", capture_window["duration_label"]),
        ("Capture Date", capture_window["date_label"]),
        ("File Size", _format_file_size(file_size_bytes) if file_size_bytes else "Unavailable"),
        ("Total Packets", _format_int(capture_window["total_frames"])),
        ("Network", _infer_network_context(parsed, technologies_seen)),
        ("Test Scenario", scenario),
        ("A-party", _format_party_identity_summary(party_identities[0]) if party_identities else (a_party or "Unknown")),
        ("B-party", _format_party_identity_summary(party_identities[1]) if len(party_identities) > 1 else (b_party or "Unknown")),
    ]

    return {
        "headline": headline,
        "trace_type": trace_type,
        "scenario": scenario,
        "a_party": a_party,
        "b_party": b_party,
        "subscriber_imsi": subscriber,
        "top_protocols": top_protocols,
        "technologies_seen": technologies_seen,
        "dominant_protocol": dominant_protocol,
        "overview": overview,
        "party_identities": party_identities,
        "node_inventory": node_inventory,
        "protocol_breakdown": protocol_breakdown,
        "observations": observations,
        "topology": topology,
        "summary_lines": [
            f"Primary trace type: {trace_type}",
            f"Test scenario: {scenario}",
            f"Capture window: {capture_window['window_label']}",
            f"Technologies observed: {', '.join(technologies_seen) if technologies_seen else 'Unknown'}",
            f"Dominant protocol: {dominant_protocol}",
            f"A-party: {_format_party_identity_summary(party_identities[0]) if party_identities else (a_party or 'Unknown')}",
            f"B-party: {_format_party_identity_summary(party_identities[1]) if len(party_identities) > 1 else (b_party or 'Unknown')}",
            f"Sessions correlated: {len(sessions)}",
        ],
    }


def build_session_details_summary(session: dict) -> dict:
    protocols = session.get("protocols", [])
    technologies = session.get("technologies", [])
    call_type = _infer_session_type(session)
    a_party = _display_session_party(session)
    b_party = session.get("called") or "Unknown"
    parsed_subset = _session_parsed_subset(session)
    protocol_counts = {
        key.upper(): len(value)
        for key, value in parsed_subset.items()
        if isinstance(value, list) and value
    }
    selected_filter = _build_session_selected_filter(session, parsed_subset)
    correlation_anchors = _build_session_correlation_anchors(session, parsed_subset, selected_filter)
    node_inventory = _build_session_node_inventory(session, parsed_subset, protocol_counts)
    topology = _build_session_topology_inference(session, parsed_subset, protocol_counts)
    anchor_preview = "; ".join(
        f"{item['label']} {item['value']}"
        for item in correlation_anchors[:4]
    )
    return {
        "headline": f"{call_type} session",
        "call_type": call_type,
        "a_party": a_party,
        "b_party": b_party,
        "protocols": protocols,
        "technologies": technologies,
        "selected_filter": selected_filter,
        "correlation_anchors": correlation_anchors,
        "node_inventory": node_inventory,
        "topology": topology,
        "summary_lines": [
            f"Selected filter: {selected_filter['label']} = {selected_filter['value']}",
            f"Correlation anchors: {anchor_preview or 'No explicit identity anchors observed'}",
            f"Call/session type: {call_type}",
            f"Technologies: {', '.join(technologies) if technologies else 'Unknown'}",
            f"Protocols: {', '.join(protocols) if protocols else 'Unknown'}",
            f"A-party: {a_party}",
            f"B-party: {b_party}",
            f"Flow summary: {session.get('flow_summary') or 'Unavailable'}",
        ],
    }


def _build_session_selected_filter(session: dict, parsed_subset: dict) -> dict:
    candidates = _session_anchor_candidates(session, parsed_subset)
    preferred_labels = (
        "Call-ID",
        "Tunnel ID (TEID)",
        "Diameter Session-ID",
        "PFCP SEID",
        "Access UE ID",
        "IMSI",
        "MSISDN",
        "Subscriber IP",
        "Session-ID",
    )
    for label in preferred_labels:
        match = next((candidate for candidate in candidates if candidate["label"] == label), None)
        if match:
            return {
                "label": match["label"],
                "value": match["value"],
                "source": match["source"],
            }

    session_id = session.get("session_id") or session.get("call_id") or "Unknown"
    return {
        "label": "Session-ID",
        "value": str(session_id),
        "source": "Session seed",
    }


def _build_session_correlation_anchors(session: dict, parsed_subset: dict, selected_filter: dict) -> list[dict]:
    candidates = _session_anchor_candidates(session, parsed_subset)
    anchors: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(anchor: dict) -> None:
        label = str(anchor.get("label") or "").strip()
        value = str(anchor.get("value") or "").strip()
        if not label or not value:
            return
        key = (label, value)
        if key in seen:
            return
        seen.add(key)
        anchors.append({
            "label": label,
            "value": value,
            "source": anchor.get("source") or "Correlation engine",
        })

    if selected_filter:
        add(selected_filter)

    order = {
        "Call-ID": 0,
        "Diameter Session-ID": 1,
        "Tunnel ID (TEID)": 2,
        "GTP F-TEID": 3,
        "GTP TID": 4,
        "PFCP SEID": 5,
        "Access UE ID": 6,
        "IMSI": 7,
        "MSISDN": 8,
        "Subscriber IP": 9,
        "APN": 10,
        "Stream ID": 11,
        "Transaction ID": 12,
        "Session-ID": 13,
    }
    for candidate in sorted(candidates, key=lambda item: order.get(item["label"], 99)):
        add(candidate)

    return anchors[:10]


def _session_anchor_candidates(session: dict, parsed_subset: dict) -> list[dict]:
    candidates: list[dict] = []

    def add(label: str, value: str | None, source: str) -> None:
        text = str(value or "").strip()
        if not text:
            return
        candidates.append({"label": label, "value": text, "source": source})

    sip_msgs = parsed_subset.get("sip", []) or session.get("sip_msgs", [])
    dia_msgs = parsed_subset.get("diameter", []) or session.get("dia_msgs", [])
    gtp_msgs = parsed_subset.get("gtp", []) or session.get("gtp_msgs", [])
    access_msgs = [
        *(parsed_subset.get("s1ap", []) or []),
        *(parsed_subset.get("ngap", []) or []),
        *(parsed_subset.get("ranap", []) or []),
        *(parsed_subset.get("bssap", []) or []),
    ]
    pfcp_msgs = parsed_subset.get("pfcp", []) or session.get("pfcp_msgs", [])
    generic_msgs = session.get("generic_msgs", [])

    if sip_msgs:
        add("Call-ID", _first_value(sip_msgs, ("call_id",)) or session.get("call_id"), "SIP identity seed")
    add("Diameter Session-ID", _first_value(dia_msgs, ("session_id",)), "Diameter subscriber/auth session")
    add("Tunnel ID (TEID)", _first_value(gtp_msgs, ("gtp.teid",)), "GTP tunnel identity")
    add("GTP F-TEID", _first_value(gtp_msgs, ("gtp.f_teid",)), "GTP forwarding tunnel identity")
    add("GTP TID", _first_value(gtp_msgs, ("gtp.tid",)), "GTP transaction identity")
    add("PFCP SEID", _first_value(pfcp_msgs, ("pfcp.seid",)), "PFCP N4 session identity")
    add(
        "Access UE ID",
        _first_value(access_msgs + generic_msgs, ("s1ap_mme_ue_id", "s1ap_enb_ue_id", "ngap_amf_ue_id", "ngap_ran_ue_id")),
        "Access control-plane UE identity",
    )
    add(
        "IMSI",
        session.get("imsi")
        or _first_value(dia_msgs, ("imsi",))
        or _first_value(gtp_msgs, ("gtpv2.imsi", "imsi"))
        or _first_value(access_msgs + generic_msgs, ("imsi",)),
        "Subscriber identity",
    )
    add(
        "MSISDN",
        session.get("msisdn")
        or _first_value(dia_msgs, ("msisdn",))
        or _first_value(access_msgs + generic_msgs, ("msisdn",)),
        "Subscriber number",
    )
    add(
        "Subscriber IP",
        session.get("subscriber_ip")
        or _first_value(dia_msgs, ("framed_ip",))
        or _first_value(gtp_msgs, ("gtp.subscriber_ip",))
        or _first_value(access_msgs + generic_msgs, ("radius_framed_ip",)),
        "UE IP / framed IP anchor",
    )
    add("APN", _first_value(gtp_msgs, ("gtp.apn",)), "Packet data network context")
    add("Stream ID", _first_value(access_msgs + generic_msgs, ("stream_id",)), "Transport stream fallback")
    add("Transaction ID", _first_value(access_msgs + generic_msgs, ("transaction_id",)), "Generic transaction fallback")
    add("Session-ID", session.get("session_id") or session.get("call_id"), "Session seed")

    return candidates


def _first_value(items: list, keys: tuple[str, ...]) -> str | None:
    for item in items:
        for key in keys:
            value = item.get(key) if isinstance(item, dict) else None
            if value:
                return str(value)
    return None


def _session_parsed_subset(session: dict) -> dict:
    return {
        "sip": session.get("sip_msgs", []),
        "diameter": session.get("dia_msgs", []),
        "inap": session.get("inap_msgs", []),
        "gtp": session.get("gtp_msgs", []),
        "s1ap": session.get("s1ap_msgs", []),
        "ngap": session.get("ngap_msgs", []),
        "ranap": session.get("ranap_msgs", []),
        "bssap": session.get("bssap_msgs", []),
        "map": session.get("map_msgs", []),
        "http": session.get("http_msgs", []),
        "tcp": session.get("tcp_msgs", []),
        "udp": session.get("udp_msgs", []),
        "sctp": session.get("sctp_msgs", []),
        "dns": session.get("dns_msgs", []),
        "icmp": session.get("icmp_msgs", []),
        "nas_eps": session.get("nas_eps_msgs", []),
        "nas_5gs": session.get("nas_5gs_msgs", []),
        "pfcp": session.get("pfcp_msgs", []),
        "radius": session.get("radius_msgs", []),
    }


def _build_session_node_inventory(session: dict, parsed_subset: dict, protocol_counts: dict) -> list[dict]:
    inventory = list(_build_node_inventory(parsed_subset, protocol_counts))
    seen = {(item.get("role"), item.get("ip")) for item in inventory}

    subscriber_ip = session.get("subscriber_ip")
    if subscriber_ip and ("UE", subscriber_ip) not in seen:
        inventory.insert(
            0,
            {
                "role": "UE",
                "ip": subscriber_ip,
                "protocols": [proto.upper() for proto in session.get("protocols", [])[:3]],
                "evidence": "Subscriber IP recovered from correlated Diameter / GTP context",
                "confidence": "high",
            },
        )

    return inventory


def _build_session_topology_inference(session: dict, parsed_subset: dict, protocol_counts: dict) -> dict:
    return _build_topology_inference(
        parsed_subset,
        protocol_counts,
        session.get("imsi"),
        _display_session_party(session),
        session.get("called"),
    )


def _build_capture_failure_topology(sessions: list, details: dict) -> dict:
    focus_session = _select_focus_failure_session(sessions)
    if not focus_session:
        return {
            "title": "Failure topology unavailable",
            "narrative": "Upload a capture with correlated sessions to generate an analyst-style break-path view.",
            "nodes": [],
            "edges": [],
            "insights": [],
        }

    topology = _build_failure_topology(
        focus_session,
        node_inventory=_build_session_node_inventory(
            focus_session,
            _session_parsed_subset(focus_session),
            {
                key.upper(): len(value)
                for key, value in _session_parsed_subset(focus_session).items()
                if isinstance(value, list) and value
            },
        ),
        capture_node_inventory=details.get("node_inventory", []),
    )
    topology["scope"] = "capture-lead"
    topology["focus_session_id"] = focus_session.get("session_id") or focus_session.get("call_id")
    return topology


def _select_focus_failure_session(sessions: list) -> dict | None:
    if not sessions:
        return None

    abnormal = [
        session
        for session in sessions
        if _session_has_abnormal_rca(session)
    ]
    candidates = abnormal or list(sessions)
    return max(
        candidates,
        key=lambda session: (
            float((session.get("hybrid_rca") or session.get("rca", {})).get("priority_score", session.get("priority_score", 0)) or 0),
            float((session.get("hybrid_rca") or session.get("rca", {})).get("confidence_pct", 0) or 0),
            float(session.get("duration_ms", 0) or 0),
        ),
    )


def _build_failure_topology(
    session: dict,
    *,
    node_inventory: list[dict] | None = None,
    capture_node_inventory: list[dict] | None = None,
) -> dict:
    flow = [
        item for item in session.get("flow", [])
        if item.get("src") and item.get("dst")
    ]
    if not flow:
        return {
            "title": "Failure topology unavailable",
            "narrative": "No session flow data is available for analyst-style topology rendering.",
            "nodes": [],
            "edges": [],
            "insights": [],
        }

    preferred_flow = [
        item for item in flow
        if str(item.get("protocol") or "").upper() not in {"TCP", "UDP", "SCTP"}
    ] or flow
    rca = session.get("hybrid_rca") or session.get("rca", {})
    has_failure_marker = any(
        _flow_item_is_failure(item)
        for item in preferred_flow
    )
    abnormal = _session_has_abnormal_rca(session) or has_failure_marker
    failure_event = next(
        (item for item in reversed(preferred_flow) if _flow_item_is_failure(item)),
        None,
    )

    inventory_by_address = {}
    for item in [*(node_inventory or []), *(capture_node_inventory or [])]:
        address = str(item.get("ip") or item.get("address") or "").strip()
        if address and address not in inventory_by_address:
            inventory_by_address[address] = item

    nodes_by_id: dict[str, dict] = {}
    edges_by_key: dict[tuple[str, str, str], dict] = {}
    failure_edge_key: tuple[str, str, str] | None = None
    failure_anchor_id: str | None = None

    for item in preferred_flow:
        src_node = _resolve_failure_topology_node(item.get("src"), inventory_by_address)
        dst_node = _resolve_failure_topology_node(item.get("dst"), inventory_by_address)
        nodes_by_id.setdefault(src_node["id"], src_node)
        nodes_by_id.setdefault(dst_node["id"], dst_node)
        if src_node["id"] == dst_node["id"]:
            continue

        protocol = str(item.get("protocol") or "UNKNOWN").upper()
        key = (src_node["id"], dst_node["id"], protocol)
        edge = edges_by_key.setdefault(
            key,
            {
                "source": src_node["id"],
                "target": dst_node["id"],
                "protocol": protocol,
                "label": _failure_edge_label(item),
                "count": 0,
                "status": "normal",
            },
        )
        edge["count"] += 1
        if _flow_item_is_failure(item):
            edge["status"] = "failure-path"

        if item is failure_event:
            failure_edge_key = key
            failure_anchor_id = _failure_anchor_node_id(item, src_node["id"], dst_node["id"])

    if abnormal and failure_event and failure_anchor_id:
        failure_label = _failure_sink_label(session, rca, failure_event)
        nodes_by_id["failure"] = {
            "id": "failure",
            "label": failure_label,
            "role": "Failure",
            "address": "",
            "status": "failure",
            "confidence": "high" if rca.get("confidence_pct", 0) else "medium",
            "evidence": rca.get("rca_summary") or rca.get("rca_detail") or "Failure sink inferred from RCA and last break marker",
            "protocols": [],
        }
        edges_by_key[(failure_anchor_id, "failure", "FAILURE")] = {
            "source": failure_anchor_id,
            "target": "failure",
            "protocol": "FAILURE",
            "label": _failure_edge_label(failure_event),
            "count": 1,
            "status": "failure",
        }
        anchor = nodes_by_id.get(failure_anchor_id)
        if anchor and anchor.get("status") != "failure":
            anchor["status"] = "implicated"

    if abnormal and failure_edge_key and failure_edge_key in edges_by_key:
        edge = edges_by_key[failure_edge_key]
        edge["status"] = "failure-path"
        nodes_by_id[edge["source"]]["status"] = nodes_by_id[edge["source"]].get("status") or "implicated"
        if nodes_by_id[edge["source"]].get("status") != "failure":
            nodes_by_id[edge["source"]]["status"] = "implicated"
        if nodes_by_id[edge["target"]].get("status") not in {"failure", "implicated"}:
            nodes_by_id[edge["target"]]["status"] = "implicated"

    nodes = list(nodes_by_id.values())
    edges = sorted(
        edges_by_key.values(),
        key=lambda edge: (
            0 if edge.get("status") == "failure" else 1 if edge.get("status") == "failure-path" else 2,
            -int(edge.get("count", 0)),
            edge.get("protocol", ""),
        ),
    )[:7]

    narrative = _failure_topology_narrative(session, rca, failure_event, nodes)
    insights = _failure_topology_insights(session, rca, failure_event, nodes, edges)
    title = (
        f"Failure Topology · {rca.get('rca_title') or rca.get('rca_label', 'Session View').replace('_', ' ').title()}"
        if abnormal
        else "Service Path Topology"
    )

    return {
        "title": title,
        "narrative": narrative,
        "focus_session_id": session.get("session_id") or session.get("call_id"),
        "rca_label": rca.get("rca_label", "UNKNOWN"),
        "has_failure": bool(abnormal and failure_event),
        "nodes": nodes,
        "edges": edges,
        "insights": insights,
    }


def _session_has_abnormal_rca(session: dict) -> bool:
    rca = session.get("hybrid_rca") or session.get("rca", {})
    label = str(rca.get("rca_label") or "").upper().strip()
    if not label or label == "UNKNOWN":
        return False
    if label.startswith("NORMAL"):
        return False
    return True


def _resolve_failure_topology_node(node_label: str | None, inventory_by_address: dict) -> dict:
    raw_type, address = _parse_topology_node_label(node_label)
    inventory = inventory_by_address.get(address) if address else None
    role = str(inventory.get("role") if inventory else "").strip() or _friendly_node_role(raw_type, address)
    collapse_roles = {
        "UE",
        "P-CSCF",
        "I/S-CSCF",
        "HSS/PCRF",
        "MME",
        "AMF",
        "AMF/MME",
        "gNB",
        "eNB",
        "gNB/eNB",
        "UPF/SGW",
        "SMF/PGW-C",
        "NAS / Access Device",
        "RADIUS Server",
        "HLR/HSS",
    }
    node_id = role if role in collapse_roles else (address or role or "Unknown")
    label = role if role in collapse_roles else (_mask_ip(address) if address else role or "Unknown")
    return {
        "id": node_id,
        "label": label,
        "role": role or "Unknown",
        "address": address,
        "status": "normal",
        "confidence": (inventory or {}).get("confidence", "low"),
        "evidence": (inventory or {}).get("evidence", ""),
        "protocols": (inventory or {}).get("protocols", []),
        "zone": raw_type,
    }


def _parse_topology_node_label(node_label: str | None) -> tuple[str, str]:
    text = str(node_label or "").strip()
    if not text:
        return "UNKNOWN", ""
    if "\n" not in text:
        return "UNKNOWN", text
    role, address = text.split("\n", 1)
    return role.strip(), address.strip()


def _friendly_node_role(raw_type: str, address: str) -> str:
    normalized = str(raw_type or "").upper()
    if normalized == "IMS":
        return "IMS Core"
    if normalized == "CORE":
        return "Core Node"
    if normalized in {"EXT", "EXTERNAL"}:
        return f"External {_mask_ip(address)}" if address else "External Peer"
    if normalized == "UE":
        return "UE"
    return _mask_ip(address) if address else "Unknown"


def _flow_item_is_failure(item: dict) -> bool:
    if item.get("failure"):
        return True

    protocol = str(item.get("protocol") or "").upper()
    message = str(item.get("message") or item.get("short_label") or "").upper()
    details = item.get("details") or {}

    if protocol == "SIP":
        match = re.match(r"^(\d{3})", message)
        if match:
            code = int(match.group(1))
            return code >= 400 and code not in {401, 407}
        return any(marker in message for marker in ("TIMEOUT", "REJECT", "DECLINE", "NOT FOUND", "FAIL"))

    if protocol == "DIAMETER":
        return bool(item.get("failure")) or bool(details.get("result_code")) and str(details.get("result_code")) not in {"2001", "1001"}

    if protocol == "GTP":
        cause = str(details.get("cause_code") or "").strip()
        if cause and cause not in {"16", "128"}:
            return True
        return any(marker in message for marker in ("REJECT", "FAIL", "ERROR", "NOT FOUND"))

    return any(marker in message for marker in ("REJECT", "FAIL", "ERROR", "TIMEOUT", "ABORT", "DENIED", "UNREACHABLE"))


def _failure_anchor_node_id(item: dict, source_id: str, target_id: str) -> str:
    protocol = str(item.get("protocol") or "").upper()
    message = str(item.get("message") or "").upper()
    if protocol == "SIP" and re.match(r"^\d{3}", message):
        return target_id
    return source_id


def _failure_sink_label(session: dict, rca: dict, failure_event: dict | None) -> str:
    if (rca.get("rca_label") or "").upper() == "SUBSCRIBER_UNREACHABLE":
        return "UE Failure"
    if rca.get("rca_title"):
        return rca["rca_title"]
    if rca.get("rca_label") and rca.get("rca_label") != "UNKNOWN":
        return str(rca["rca_label"]).replace("_", " ").title()
    if failure_event:
        return _failure_edge_label(failure_event)
    return "Failure"


def _failure_edge_label(item: dict | None) -> str:
    if not item:
        return "Failure"
    label = str(item.get("short_label") or item.get("message") or item.get("protocol") or "Failure").strip()
    label = re.sub(r"\s+", " ", label)
    return label[:42]


def _failure_topology_narrative(session: dict, rca: dict, failure_event: dict | None, nodes: list[dict]) -> str:
    visible_roles = [node.get("label") for node in nodes if node.get("role") != "Failure"][:4]
    path_text = " -> ".join(visible_roles) if visible_roles else "correlated service nodes"
    if failure_event:
        return (
            f"The correlated path traverses {path_text}. "
            f"The highlighted break marker is {_failure_edge_label(failure_event)} on {failure_event.get('protocol') or 'UNKNOWN'}, "
            f"which is being used to explain the {rca.get('rca_title') or rca.get('rca_label', 'current RCA').replace('_', ' ').lower()} outcome."
        )
    if rca.get("rca_summary"):
        return rca["rca_summary"]
    return f"The correlated path traverses {path_text}. No strong failure edge was isolated for this session."


def _failure_topology_insights(session: dict, rca: dict, failure_event: dict | None, nodes: list[dict], edges: list[dict]) -> list[str]:
    insights: list[str] = []
    if failure_event:
        insights.append(f"Break marker: {_failure_edge_label(failure_event)} ({failure_event.get('protocol') or 'UNKNOWN'})")
    if rca.get("confidence_pct"):
        insights.append(f"RCA confidence: {int(round(float(rca.get('confidence_pct', 0))))}%")
    implicated = [node for node in nodes if node.get("status") in {"implicated", "failure"}]
    if implicated:
        focus = implicated[0]
        if focus.get("evidence"):
            insights.append(f"Focus node: {focus.get('label')} inferred from {focus.get('evidence')}")
        else:
            insights.append(f"Focus node: {focus.get('label')} ({focus.get('role')})")
    if session.get("correlation_methods"):
        method_text = ", ".join(str(method).split(":")[-1].replace("_", " ") for method in session.get("correlation_methods", [])[:3])
        insights.append(f"Correlation path: {method_text}")
    if session.get("subscriber_ip"):
        insights.append(f"Subscriber IP anchor: {session.get('subscriber_ip')}")
    if not insights and edges:
        insights.append(f"Observed {len(edges)} correlated edge(s) across the selected session.")
    return insights[:4]


def _display_session_party(session: dict) -> str:
    msisdn = session.get("msisdn")
    if msisdn:
        return str(msisdn)
    calling = session.get("calling")
    return str(calling) if calling else "Unknown"


def _build_party_identities(parsed: dict, sessions: list, subscriber: str | None, calling_party: str | None, called_party: str | None) -> list[dict]:
    a_imsi = subscriber
    b_imsi = _find_related_imsi(parsed, called_party)
    a_network = _infer_party_network(parsed, calling_party, a_imsi)
    b_network = _infer_party_network(parsed, called_party, b_imsi)

    return [
        {
            "label": "A-party",
            "msisdn": calling_party or "Unknown",
            "imsi": a_imsi or "Not observed",
            "network": a_network["name"],
            "network_source": a_network["source"],
            "source": _subscriber_sources(parsed, sessions),
            "confidence": "high" if a_imsi and calling_party else "medium" if calling_party else "low",
        },
        {
            "label": "B-party",
            "msisdn": called_party or "Unknown",
            "imsi": b_imsi or "Not observed",
            "network": b_network["name"],
            "network_source": b_network["source"],
            "source": "SIP destination / called party" if called_party else "Unavailable",
            "confidence": "medium" if b_imsi else ("low" if called_party else "low"),
        },
    ]


def _build_node_inventory(parsed: dict, protocol_counts: dict) -> list[dict]:
    nodes = []
    seen = set()

    def add_node(role: str, ip: str | None, protocols: list[str], evidence: str, confidence: str) -> None:
        key = (role, ip)
        if not ip or key in seen:
            return
        seen.add(key)
        nodes.append(
            {
                "role": role,
                "ip": ip,
                "protocols": protocols,
                "evidence": evidence,
                "confidence": confidence,
            }
        )

    ngap_pair = _top_pair(parsed.get("ngap", []))
    s1ap_pair = _top_pair(parsed.get("s1ap", []))
    pfcp_pair = _top_pair(parsed.get("pfcp", []))
    gtpv2_pair = _top_pair([packet for packet in parsed.get("gtp", []) if packet.get("gtpv2.message_type")])
    gtpu_pair = _top_pair([packet for packet in parsed.get("gtp", []) if not packet.get("gtpv2.message_type")])
    sip_pair = _top_pair(parsed.get("sip", []))
    diameter_pair = _top_pair(parsed.get("diameter", []))
    radius_pair = _top_pair(parsed.get("radius", []))

    add_node("gNB", ngap_pair["src"], ["NGAP"], "Top NGAP source endpoint", "high" if ngap_pair["src"] else "low")
    add_node("AMF", ngap_pair["dst"], ["NGAP"], "Top NGAP destination endpoint", "high" if ngap_pair["dst"] else "low")

    add_node("eNB", s1ap_pair["src"], ["S1AP"], "Top S1AP source endpoint", "high" if s1ap_pair["src"] else "low")
    mme_confidence = "high" if s1ap_pair["dst"] and diameter_pair["src"] == s1ap_pair["dst"] else "medium"
    mme_evidence = "S1AP control endpoint with Diameter adjacency" if mme_confidence == "high" else "Top S1AP destination endpoint"
    add_node("MME", s1ap_pair["dst"], ["S1AP", "Diameter"] if mme_confidence == "high" else ["S1AP"], mme_evidence, mme_confidence)

    smf_ip = pfcp_pair["dst"] or gtpv2_pair["dst"]
    upf_ip = gtpu_pair["src"] or pfcp_pair["src"]
    add_node("SMF/PGW-C", smf_ip, [p for p in ["PFCP", "GTPv2"] if protocol_counts.get(p.upper() if p != "GTPv2" else "GTP")], "PFCP/GTPv2 control-plane endpoint", "high" if pfcp_pair["dst"] else "medium")
    add_node("UPF/SGW", upf_ip, ["GTP-U", "PFCP"], "User-plane endpoint participating in GTP-U and PFCP", "high" if gtpu_pair["src"] and pfcp_pair["src"] else "medium")

    pcscf_confidence = "high" if sip_pair["src"] else "low"
    add_node("P-CSCF", sip_pair["src"], ["SIP"], "Top SIP ingress/core-facing endpoint", pcscf_confidence)

    icscf_ip = sip_pair["dst"] or diameter_pair["dst"]
    icscf_protocols = ["SIP"]
    if diameter_pair["dst"] == icscf_ip and icscf_ip:
        icscf_protocols.append("Diameter")
    add_node("I/S-CSCF", icscf_ip, icscf_protocols, "SIP core endpoint with optional Diameter adjacency", "high" if sip_pair["dst"] else "medium")

    if diameter_pair["dst"] and diameter_pair["dst"] not in seen:
        add_node("HSS/PCRF", diameter_pair["dst"], ["Diameter"], "Diameter peer carrying subscriber or policy state", "medium")

    add_node("NAS / Access Device", radius_pair["src"], ["RADIUS"], "Top RADIUS request source endpoint", "medium" if radius_pair["src"] else "low")
    add_node("RADIUS Server", radius_pair["dst"], ["RADIUS"], "Top RADIUS response endpoint", "medium" if radius_pair["dst"] else "low")

    if protocol_counts.get("MAP"):
        map_pair = _top_pair(parsed.get("map", []))
        add_node("HLR/HSS", map_pair["dst"], ["MAP"], "MAP signalling peer suggesting legacy subscriber-data interworking", "medium")

    return nodes


def _subscriber_sources(parsed: dict, sessions: list) -> str:
    sources = []
    for key, label in (
        ("nas_eps", "NAS_EPS"),
        ("nas_5gs", "NAS_5GS"),
        ("map", "MAP"),
        ("diameter", "Diameter"),
        ("gtp", "GTPv2"),
    ):
        for packet in parsed.get(key, []):
            if _looks_like_imsi(packet.get("imsi") or packet.get("gtpv2.imsi")):
                sources.append(label)
                break
    if not sources and any(_looks_like_imsi(session.get("imsi")) for session in sessions):
        sources.append("Session correlation")
    return ", ".join(sources) or "Unavailable"


def _find_related_imsi(parsed: dict, msisdn: str | None) -> str | None:
    if not msisdn:
        return None
    normalized_msisdn = _normalize_msisdn(msisdn)
    if not normalized_msisdn:
        return None

    for packet in parsed.get("diameter", []):
        packet_msisdn = _normalize_msisdn(packet.get("msisdn"))
        if packet_msisdn and packet_msisdn == normalized_msisdn and _looks_like_imsi(packet.get("imsi")):
            return str(packet.get("imsi"))

    for packet in parsed.get("map", []):
        packet_msisdn = _normalize_msisdn(packet.get("msisdn"))
        if packet_msisdn and normalized_msisdn.endswith(packet_msisdn[-len(packet_msisdn):]) and _looks_like_imsi(packet.get("imsi")):
            return str(packet.get("imsi"))

    return None


def _infer_party_network(parsed: dict, msisdn: str | None, imsi: str | None) -> dict:
    plmn_hint = _extract_party_plmn_hint(parsed, msisdn, imsi)
    if plmn_hint:
        plmn = plmn_hint["plmn"]
        return {
            "name": PLMN_NETWORKS.get(plmn, f"PLMN {plmn[:3]}-{plmn[3:]}"),
            "source": f"{plmn_hint['source']} {plmn[:3]}-{plmn[3:]}",
        }

    normalized = _normalize_msisdn(msisdn)
    if normalized and normalized.startswith("49") and len(normalized) >= 5:
        prefix = normalized[2:5]
        network = GERMAN_MSISDN_PREFIX_NETWORKS.get(prefix)
        if network:
            return {
                "name": f"{network} (heuristic)",
                "source": f"MSISDN prefix +49 {prefix}; number portability may apply",
            }

    return {"name": "Unknown", "source": "No MCC/MNC or trusted operator hint observed"}


def _extract_party_plmn_hint(parsed: dict, msisdn: str | None, imsi: str | None) -> dict | None:
    hints = []
    pattern = re.compile(r"mnc(\d{2,3})\.mcc(\d{3})", re.IGNORECASE)
    msisdn_digits = _normalize_msisdn(msisdn)
    for packet in parsed.get("sip", []):
        for field in ("from_uri", "to_uri", "uri", "host"):
            value = packet.get(field)
            if not value:
                continue
            text = str(value)
            if imsi and imsi not in text and not (msisdn_digits and msisdn_digits[-10:] in "".join(ch for ch in text if ch.isdigit())):
                continue
            match = pattern.search(text)
            if match:
                mnc, mcc = match.group(1), match.group(2)
                hints.append({"plmn": f"{mcc}{mnc}", "source": "SIP routing domain MCC/MNC"})
    if hints:
        if imsi:
            for hint in hints:
                if str(imsi).startswith(hint["plmn"]):
                    return hint
        return hints[0]

    if imsi and _looks_like_imsi(imsi):
        digits = "".join(ch for ch in str(imsi) if ch.isdigit())
        for mnc_len in (3, 2):
            candidate = digits[: 3 + mnc_len]
            if candidate in PLMN_NETWORKS:
                return {"plmn": candidate, "source": "IMSI MCC/MNC"}
    return None


def _normalize_msisdn(value: str | None) -> str | None:
    if not value:
        return None
    digits = "".join(ch for ch in str(value) if ch.isdigit())
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith("0") and len(digits) >= 10:
        digits = f"49{digits[1:]}"
    return digits or None


def _format_party_identity_summary(party: dict) -> str:
    msisdn = party.get("msisdn") or "Unknown"
    imsi = party.get("imsi") or "Not observed"
    network = party.get("network") or "Unknown"
    return f"{msisdn} · IMSI {imsi} · {network}"


def _error_category(category: str, count: int, severity: str, verdict: str) -> dict:
    return {
        "category": category,
        "count": count,
        "severity": severity,
        "verdict": verdict,
    }


def _packet_examples(packets: list, fields: tuple[str, ...], limit: int = 5) -> list[dict]:
    rows = []
    for packet in packets[:limit]:
        row = {}
        for field in fields:
            if field == "time_label":
                row[field] = _timestamp_label(packet.get("timestamp"))
            else:
                row[field] = packet.get(field)
        rows.append(row)
    return rows


def _collect_tcp_transport_issues(parsed: dict) -> list[dict]:
    issue_packets = []
    for packet in parsed.get("tcp", []):
        issue_type = _tcp_issue_type(packet)
        if not issue_type:
            continue
        packet_with_issue = dict(packet)
        packet_with_issue["issue_type"] = issue_type
        issue_packets.append(packet_with_issue)
    return issue_packets


def _tcp_issue_type(packet: dict) -> str | None:
    if _flag_true(packet.get("retransmission")) or _flag_true(packet.get("fast_retransmission")):
        return "Retransmission"
    if _flag_true(packet.get("duplicate_ack")):
        return "Duplicate ACK"
    if _flag_true(packet.get("ack_lost_segment")):
        return "ACKed Lost Segment"
    if _flag_true(packet.get("lost_segment")):
        return "Lost Segment"
    if packet.get("reset") is True or "RST" in str(packet.get("message", "")).upper():
        return "TCP Reset"
    return None


def _tcp_issue_breakdown(packets: list) -> Counter:
    return Counter(packet.get("issue_type", "Unknown") for packet in packets)


def _describe_tcp_issue_breakdown(breakdown: Counter, include_counts: bool = False) -> str:
    ordered = ["ACKed Lost Segment", "Retransmission", "Duplicate ACK", "Lost Segment", "TCP Reset"]
    parts = []
    for label in ordered:
        count = int(breakdown.get(label, 0))
        if count <= 0:
            continue
        parts.append(f"{label} ({count})" if include_counts else label)
    return ", ".join(parts) if parts else "No notable transport anomalies"


def _timestamp_label(timestamp: float | None) -> str:
    if timestamp is None:
        return "Unknown"
    try:
        return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).strftime("%H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "Unknown"


def _flag_true(value) -> bool:
    normalized = str(value).strip().lower()
    return normalized not in {"", "0", "false", "none", "nan"}


def _build_error_timeline(sip_401_packets: list, sip_packets: list, gtp_context_not_found: list, ngap_release: list, s1ap_release: list) -> list[dict]:
    events = []
    if sip_401_packets:
        first = min(sip_401_packets, key=lambda p: float(p.get("timestamp") or 0))
        events.append({"time": _timestamp_label(first.get("timestamp")), "event": "SIP 401 AKA challenge", "severity": "none"})
    sip_success = [p for p in sip_packets if str(p.get("status_code")) == "200"]
    if sip_success:
        first = min(sip_success, key=lambda p: float(p.get("timestamp") or 0))
        events.append({"time": _timestamp_label(first.get("timestamp")), "event": "SIP 200 OK registration / call progress", "severity": "none"})
    if ngap_release:
        first = min(ngap_release, key=lambda p: float(p.get("timestamp") or 0))
        events.append({"time": _timestamp_label(first.get("timestamp")), "event": "NGAP UE context release cycle", "severity": "none"})
    if s1ap_release:
        first = min(s1ap_release, key=lambda p: float(p.get("timestamp") or 0))
        events.append({"time": _timestamp_label(first.get("timestamp")), "event": "S1AP UE context release cycle", "severity": "none"})
    for packet in gtp_context_not_found[:3]:
        events.append({"time": _timestamp_label(packet.get("timestamp")), "event": f"GTPv2 {packet.get('message') or 'Context Not Found'}", "severity": "medium"})
    events.sort(key=lambda item: item["time"])
    return events[:10]


def _build_error_recommendations(gtp_context_not_found: list, tcp_issue_packets: list, diameter_non_success: list) -> list[dict]:
    recommendations = []
    if gtp_context_not_found:
        recommendations.append(
            {
                "priority": "Medium",
                "title": "Review GTP bearer and session cleanup ordering",
                "body": "Inspect inter-RAT or session-release timing between control-plane peers. Context Not Found usually means one side removed bearer state before the peer finished cleanup.",
            }
        )
    if tcp_issue_packets:
        recommendations.append(
            {
                "priority": "Low",
                "title": "Review transport loss on affected paths",
                "body": "Correlate transport-analysis markers with GTP-U, PFCP, or IMS links before treating them as service-impacting. Multi-point captures can amplify apparent tunnel or signaling-path noise.",
            }
        )
    if diameter_non_success:
        dominant = next((packet.get("protocol_intelligence") for packet in diameter_non_success if packet.get("protocol_intelligence")), None)
        recommendations.append(
            {
                "priority": "Medium",
                "title": "Inspect Diameter semantic failures",
                "body": (
                    "Check whether non-success Diameter responses align with subscriber, policy, routing, or charging problems rather than harmless informational exchanges."
                    if not dominant else
                    f"Start from {dominant.get('name')} ({dominant.get('code')}) and validate whether the failure matches subscriber state, routing, or service-policy context."
                ),
            }
        )
    if not recommendations:
        recommendations.append(
            {
                "priority": "Info",
                "title": "No high-confidence protocol errors detected",
                "body": "Most flagged events in this trace look consistent with normal IMS or mobility control behavior. Focus on session-level RCA for any remaining outliers.",
            }
        )
    return recommendations


def _build_error_assessment(gtp_context_not_found: list, tcp_issue_packets: list, diameter_non_success: list, details: dict) -> str:
    if gtp_context_not_found:
        return (
            f"The trace is broadly healthy at the IMS signalling layer, but it contains {len(gtp_context_not_found)} "
            "GTPv2 context-synchronization issue(s) that look like genuine bearer cleanup problems. "
            "Transport anomalies should be reviewed as supporting context, not as the primary root cause."
        )
    if diameter_non_success:
        return (
            "The trace contains protocol-level non-success indications outside the SIP registration challenge flow. "
            "Diameter responses should be reviewed alongside the session RCA to separate informational results from real AAA or policy failures."
        )
    if tcp_issue_packets:
        return (
            f"The trace does not show a strong protocol-control failure, but it does contain {len(tcp_issue_packets)} transport-analysis marker(s). "
            "That likely reflects packet loss, tunnel visibility gaps, or mild transport instability rather than a hard service outage."
        )
    return f"The capture looks operationally healthy. {details.get('scenario', 'Service validation')} completes without a strong protocol-level failure signature."


def _extract_trace_parties(parsed: dict, sessions: list, subscriber: str | None = None) -> tuple[str | None, str | None]:
    for packet in parsed.get("sip", []):
        caller = _extract_number(packet.get("from_uri"))
        callee = _extract_number(packet.get("to_uri"))
        if caller or callee:
            return caller or packet.get("src_ip"), callee or packet.get("dst_ip")

    for session in sessions:
        if session.get("calling") or session.get("called"):
            return session.get("calling"), session.get("called")

    for packet in parsed.get("diameter", []):
        if packet.get("msisdn"):
            return packet.get("msisdn"), packet.get("destination_host") or packet.get("apn") or packet.get("dst_ip")

    if subscriber:
        for packet in parsed.get("diameter", []):
            if packet.get("imsi") == subscriber or packet.get("msisdn"):
                return packet.get("msisdn") or packet.get("src_ip"), packet.get("apn") or packet.get("dst_ip")

    for packet in parsed.get("radius", []):
        if packet.get("radius_calling_station_id") or packet.get("radius_called_station_id") or packet.get("radius_user_name"):
            return (
                packet.get("radius_calling_station_id") or packet.get("radius_user_name") or packet.get("src_ip"),
                packet.get("radius_called_station_id") or packet.get("dst_ip"),
            )

    for packet in parsed.get("map", []):
        if packet.get("msisdn") or packet.get("dst_ip"):
            return packet.get("msisdn") or packet.get("src_ip"), packet.get("dst_ip")

    for key in ("sip", "diameter", "s1ap", "ngap", "ranap", "bssap", "http", "dns", "icmp", "nas_eps", "nas_5gs", "tcp", "udp", "sctp"):
        for packet in parsed.get(key, []):
            if packet.get("src_ip") or packet.get("dst_ip"):
                return packet.get("src_ip"), packet.get("dst_ip")

    return None, None


def _infer_trace_type(protocol_counts: dict, technologies_seen: list, protocol_breakdown: list | None = None) -> str:
    top_family = (protocol_breakdown or [{}])[0].get("label", "") if protocol_breakdown else ""
    if protocol_counts.get("SIP") and protocol_counts.get("DIAMETER"):
        return "IMS call trace"
    if protocol_counts.get("RADIUS") and not (protocol_counts.get("SIP") or protocol_counts.get("DIAMETER")):
        return "RADIUS AAA trace"
    if protocol_counts.get("NGAP") and protocol_counts.get("S1AP"):
        return "Multi-RAT 5G/4G signalling trace"
    if protocol_counts.get("NGAP") or protocol_counts.get("PFCP"):
        return "5G signalling trace"
    if protocol_counts.get("S1AP") or protocol_counts.get("GTP"):
        return "LTE/4G signalling trace"
    if protocol_counts.get("MAP") and top_family == "MAP":
        return "MAP mobility/signalling trace"
    if protocol_counts.get("RANAP"):
        return "3G signalling trace"
    if protocol_counts.get("BSSAP"):
        return "2G signalling trace"
    if "HTTPS" in technologies_seen or protocol_counts.get("HTTP"):
        return "HTTP/HTTPS service trace"
    return "Mixed telecom trace"


def _build_trace_headline(trace_type: str, top_protocols: list, technologies_seen: list) -> str:
    proto_summary = ", ".join(protocol for protocol, _count in top_protocols[:2]) if top_protocols else "no dominant protocol"
    tech_summary = ", ".join(technologies_seen[:3]) if technologies_seen else "unknown technologies"
    return f"{trace_type} with {proto_summary} activity across {tech_summary}"


def _build_protocol_breakdown(parsed: dict) -> list[dict]:
    total_frames = _total_unique_frames(parsed)
    buckets = [
        ("NGAP", parsed.get("ngap", []), "5G NR access signalling"),
        ("S1AP", parsed.get("s1ap", []), "4G LTE access signalling"),
        ("PFCP", parsed.get("pfcp", []), "User-plane session management"),
        ("GTPv2", [packet for packet in parsed.get("gtp", []) if packet.get("gtpv2.message_type")], "Control-plane bearer and session setup"),
        ("GTP-U", [packet for packet in parsed.get("gtp", []) if not packet.get("gtpv2.message_type")], "User-plane data tunnelling"),
        ("SIP", parsed.get("sip", []), "IMS registration and voice signalling"),
        ("Diameter", parsed.get("diameter", []), "AAA, policy, and charging"),
        ("RADIUS", parsed.get("radius", []), "AAA access control and accounting"),
        ("GSM MAP", parsed.get("map", []), "Legacy HLR/HSS interworking"),
        ("TCP/SCTP", [*parsed.get("tcp", []), *parsed.get("sctp", [])], "Transport layer"),
    ]

    breakdown = []
    for label, packets, purpose in buckets:
        frames = _unique_frame_count(packets)
        if frames <= 0:
            continue
        breakdown.append(
            {
                "label": label,
                "frames": frames,
                "percentage": round((frames / total_frames) * 100, 1) if total_frames else 0.0,
                "purpose": purpose,
            }
        )
    return breakdown


def _capture_window(parsed: dict) -> dict:
    timestamps = []
    frame_numbers = set()
    for packets in parsed.values():
        if not isinstance(packets, list):
            continue
        for packet in packets:
            timestamp = packet.get("timestamp")
            if timestamp is not None:
                try:
                    timestamps.append(float(timestamp))
                except (TypeError, ValueError):
                    pass
            frame_number = packet.get("frame_number")
            if frame_number is not None:
                frame_numbers.add(frame_number)

    if not timestamps:
        return {
            "start": None,
            "end": None,
            "total_frames": len(frame_numbers),
            "duration_seconds": 0.0,
            "duration_label": "Unavailable",
            "date_label": "Unavailable",
            "window_label": "Unavailable",
        }

    start = min(timestamps)
    end = max(timestamps)
    start_dt = datetime.fromtimestamp(start, tz=timezone.utc)
    end_dt = datetime.fromtimestamp(end, tz=timezone.utc)
    duration_seconds = max(0.0, end - start)
    return {
        "start": start_dt,
        "end": end_dt,
        "total_frames": len(frame_numbers),
        "duration_seconds": duration_seconds,
        "duration_label": _format_duration(duration_seconds),
        "date_label": start_dt.strftime("%B %-d, %Y") if hasattr(start_dt, "strftime") else "Unavailable",
        "window_label": f"{start_dt.strftime('%H:%M:%S')} – {end_dt.strftime('%H:%M:%S')} UTC",
    }


def _build_key_observations(protocol_counts: dict, technology_counts: dict, protocol_breakdown: list, sessions: list) -> list[str]:
    observations = []
    if protocol_counts.get("NGAP") and protocol_counts.get("S1AP"):
        observations.append("Dual radio access is visible, with both 5G NGAP and 4G S1AP signalling present in the same capture.")
    if protocol_counts.get("SIP") and protocol_counts.get("DIAMETER"):
        observations.append("The capture contains a full IMS control stack, including SIP signalling and Diameter-based subscriber, policy, or charging exchanges.")
    if protocol_counts.get("RADIUS"):
        observations.append("RADIUS signalling is present, which gives visibility into access authentication, authorization, or accounting exchanges beyond Diameter-only control.")
    if any(item["label"] == "GTP-U" and item["frames"] > 0 for item in protocol_breakdown):
        observations.append("User-plane tunnelling is present through GTP-U, so the trace includes both control-plane setup and bearer-side traffic.")
    if protocol_counts.get("PFCP") and any(item["label"] == "GTPv2" for item in protocol_breakdown):
        observations.append("Core session control is visible through both PFCP and GTPv2, which is a strong indicator of end-to-end packet-core session orchestration.")
    if protocol_counts.get("MAP"):
        observations.append("Legacy SS7 or MAP interworking is present, which suggests HLR/HSS interoperability or subscriber-data lookup beyond pure EPC/5GC signalling.")
    if len([tech for tech, count in technology_counts.items() if count > 0]) >= 4:
        observations.append("This is a multi-interface capture spanning access, core control, IMS, and transport layers, which makes it suitable for end-to-end RCA.")
    if not observations and sessions:
        observations.append("The capture provides enough correlated telecom sessions to build a protocol-aware end-to-end service narrative.")
    return observations[:5]


def _build_topology_inference(parsed: dict, protocol_counts: dict, subscriber: str | None, calling_party: str | None, called_party: str | None) -> dict:
    access_peer = _top_pair(parsed.get("ngap", []) or parsed.get("s1ap", []))
    core_user_peer = _top_pair(parsed.get("pfcp", []) or parsed.get("gtp", []))
    user_plane_peer = _top_pair([packet for packet in parsed.get("gtp", []) if not packet.get("gtpv2.message_type")])
    ims_peer = _top_pair(parsed.get("sip", []))
    diameter_peer = _top_pair(parsed.get("diameter", []))
    upf_addr = user_plane_peer["src"] or user_plane_peer["dst"] or core_user_peer["src"]
    smf_addr = core_user_peer["dst"] or core_user_peer["src"]
    pcscf_addr = ims_peer["src"] or user_plane_peer["dst"]
    icscf_addr = ims_peer["dst"] or diameter_peer["dst"]

    nodes = [
        {"role": "UE", "label": calling_party or subscriber or "Subscriber", "address": subscriber},
        {"role": "gNB/eNB", "label": "gNB/eNB", "address": access_peer["src"]},
        {"role": "AMF/MME", "label": "AMF/MME", "address": access_peer["dst"]},
        {"role": "UPF/SGW", "label": "UPF/SGW", "address": upf_addr},
        {"role": "SMF/PGW-C", "label": "SMF/PGW-C", "address": smf_addr},
        {"role": "P-CSCF", "label": "P-CSCF", "address": pcscf_addr},
        {"role": "I/S-CSCF", "label": "I/S-CSCF", "address": icscf_addr},
        {"role": "Called Party", "label": called_party or "Called party", "address": called_party},
    ]
    lines = []
    if calling_party or subscriber:
        lines.append(f"UE ({calling_party or subscriber})")
    if access_peer["src"] or access_peer["dst"]:
        lines.append(f"gNB/eNB {_mask_ip(access_peer['src'])} -> NGAP/S1AP -> AMF/MME {_mask_ip(access_peer['dst'])}")
    if upf_addr or smf_addr:
        labels = []
        if user_plane_peer["src"] or user_plane_peer["dst"]:
            labels.append("GTP-U")
        if core_user_peer["src"] or core_user_peer["dst"]:
            labels.append("PFCP/GTPv2")
        mid_label = " + ".join(labels) if labels else "User-plane control"
        lines.append(f"UPF/SGW {_mask_ip(upf_addr)} <-> {mid_label} <-> SMF/PGW-C {_mask_ip(smf_addr)}")
    if pcscf_addr or icscf_addr:
        lines.append(f"P-CSCF {_mask_ip(pcscf_addr)} -> SIP -> I/S-CSCF {_mask_ip(icscf_addr)}")
    if called_party:
        lines.append(f"SIP INVITE -> {called_party}")
    return {"nodes": nodes, "lines": lines[:5]}


def _extract_primary_subscriber(parsed: dict, sessions: list) -> str | None:
    for key in ("nas_eps", "map", "nas_5gs", "diameter", "gtp"):
        for packet in parsed.get(key, []):
            value = packet.get("imsi") or packet.get("gtpv2.imsi")
            if _looks_like_imsi(value):
                return str(value)
    for session in sessions:
        if _looks_like_imsi(session.get("imsi")):
            return str(session["imsi"])
    return None


def _infer_dominant_protocol(protocol_breakdown: list, top_protocols: list) -> str:
    if protocol_breakdown:
        meaningful = [item for item in protocol_breakdown if item["label"] not in {"TCP/SCTP"}]
        if meaningful:
            return meaningful[0]["label"]
    return top_protocols[0][0] if top_protocols else "UNKNOWN"


def _infer_test_scenario(protocol_counts: dict, technologies_seen: list) -> str:
    if protocol_counts.get("SIP") and protocol_counts.get("DIAMETER") and (protocol_counts.get("NGAP") or protocol_counts.get("S1AP")):
        return "IMS registration and mobile-originated VoIP call over a converged 5G/4G core"
    if protocol_counts.get("SIP") and protocol_counts.get("DIAMETER"):
        return "IMS registration and voice signalling validation"
    if protocol_counts.get("RADIUS"):
        return "RADIUS authentication, authorization, and accounting validation"
    if protocol_counts.get("PFCP") and protocol_counts.get("GTP"):
        return "Packet-core session establishment and bearer validation"
    if protocol_counts.get("NGAP") and protocol_counts.get("S1AP"):
        return "Multi-RAT signalling and interworking validation"
    return "Telecom signalling and service validation"


def _infer_network_context(parsed: dict, technologies_seen: list) -> str:
    if any(
        str(packet.get("src_ip", "")).startswith("62.156.") or str(packet.get("dst_ip", "")).startswith("62.156.")
        for packet in parsed.get("sip", [])
    ):
        return "Deutsche Telekom 5G/4G mobile core (IMS)"
    if "IMS" in technologies_seen and ("5G" in technologies_seen or "LTE/4G" in technologies_seen):
        return "5G/4G mobile core with IMS signalling"
    if "5G" in technologies_seen:
        return "5G mobile core signalling"
    if "LTE/4G" in technologies_seen:
        return "LTE/4G mobile core signalling"
    return "Telecom core signalling environment"


def _total_unique_frames(parsed: dict) -> int:
    frames = set()
    for packets in parsed.values():
        if not isinstance(packets, list):
            continue
        for packet in packets:
            frame = packet.get("frame_number")
            if frame is not None:
                frames.add(frame)
    return len(frames)


def _unique_frame_count(packets: list) -> int:
    frames = {packet.get("frame_number") for packet in packets if packet.get("frame_number") is not None}
    return len(frames)


def _top_pair(packets: list) -> dict:
    pairs = Counter()
    for packet in packets:
        src = packet.get("src_ip")
        dst = packet.get("dst_ip")
        if src and dst:
            pairs[(src, dst)] += 1
    if not pairs:
        return {"src": None, "dst": None}
    (src, dst), _count = pairs.most_common(1)[0]
    return {"src": src, "dst": dst}


def _extract_number(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value)
    best = None
    for token in text.replace("<", " ").replace(">", " ").replace(";", " ").replace(":", " ").split():
        normalized = token.strip()
        if normalized.startswith("tel="):
            normalized = normalized[4:]
        normalized = "".join(ch for ch in normalized if ch.isdigit() or ch == "+")
        digit_count = len("".join(ch for ch in normalized if ch.isdigit()))
        if 8 <= digit_count <= 15:
            if normalized.startswith("+"):
                return normalized
            best = best or normalized
    return best


def _looks_like_imsi(value: str | None) -> bool:
    if value is None:
        return False
    digits = "".join(ch for ch in str(value) if ch.isdigit())
    return digits.isdigit() and len(digits) >= 14


def _mask_ip(value: str | None) -> str:
    if not value:
        return "unknown"
    if ":" in value:
        parts = value.split(":")
        return ":".join(parts[:3]) + ":x"
    parts = value.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".x"
    return value


def _format_duration(seconds: float) -> str:
    minutes = seconds / 60.0
    if minutes >= 1:
        return f"~{minutes:.1f} minutes"
    return f"{seconds:.1f} seconds"


def _format_file_size(size_bytes: int) -> str:
    if size_bytes <= 0:
        return "Unavailable"
    size = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"~{size:.1f} {unit}"
        size /= 1024.0
    return f"{size_bytes} B"


def _format_int(value: int | float | None) -> str:
    return f"{int(value or 0):,}"


def _infer_session_type(session: dict) -> str:
    protocols = set(session.get("protocols", []))
    if "map" in protocols:
        return "MAP signalling"
    if "sip" in protocols:
        return "IMS call"
    if "ngap" in protocols or "pfcp" in protocols:
        return "5G session"
    if "s1ap" in protocols or "gtp" in protocols:
        return "LTE/4G session"
    if "ranap" in protocols:
        return "3G session"
    if "bssap" in protocols:
        return "2G session"
    if "http" in protocols:
        return "HTTP/HTTPS transaction"
    return "Generic telecom"
