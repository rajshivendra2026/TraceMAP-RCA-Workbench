from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import re


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
        return "IMS"
    return "EXTERNAL"


def session_summary(session: dict) -> dict:
    rca = session.get("hybrid_rca") or session.get("rca", {})
    autonomous = session.get("autonomous_rca") or {}
    packet_count = sum(
        len(session.get(key, []))
        for key in (
            "sip_msgs",
            "dia_msgs",
            "inap_msgs",
            "gtp_msgs",
            "generic_msgs",
            "dns_msgs",
            "icmp_msgs",
            "nas_eps_msgs",
            "nas_5gs_msgs",
            "ngap_msgs",
            "s1ap_msgs",
            "pfcp_msgs",
        )
    )
    return {
        "call_id": session.get("call_id"),
        "flow": session.get("flow", []),
        "graph": build_session_graph(session.get("flow", [])),
        "causal_graph": autonomous.get("session_causal_graph"),
        "flow_summary": session.get("flow_summary", ""),
        "final_sip_code": session.get("final_sip_code", ""),
        "dia_correlation": session.get("dia_correlation", ""),
        "imsi": session.get("imsi"),
        "msisdn": session.get("msisdn"),
        "duration_ms": session.get("duration_ms", 0),
        "packet_count": packet_count,
        "protocols": session.get("protocols", []),
        "technologies": session.get("technologies", []),
        "rca_label": rca.get("rca_label", "UNKNOWN"),
        "rca_title": rca.get("rca_title", rca.get("rca_label", "Unknown")),
        "rca_summary": rca.get("rca_summary", ""),
        "rca_detail": rca.get("rca_detail", ""),
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
        "recommendations": rca.get("recommendations", []),
        "decision_sources": rca.get("decision_sources", {}),
        "llm_explanation": rca.get("llm_explanation", ""),
        "pattern_match": rca.get("pattern_match"),
        "anomaly": rca.get("anomaly"),
        "causal_analysis": rca.get("causal_analysis") or autonomous.get("causal_analysis"),
        "agentic_analysis": rca.get("agentic_analysis") or autonomous.get("agentic_analysis"),
        "confidence_model": rca.get("confidence_model") or autonomous.get("confidence_model"),
        "knowledge_graph_summary": rca.get("knowledge_graph_summary") or autonomous.get("knowledge_graph_summary"),
        "timeseries_summary": rca.get("timeseries_summary") or autonomous.get("timeseries_summary"),
        "details_summary": build_session_details_summary(session),
        "root_cause": rca.get("root_cause"),
        "contributing_factors": rca.get("contributing_factors", []),
        "correlation_confidence": rca.get("correlation_confidence", 0),
    }


def build_capture_summary(parsed: dict, sessions: list, capture_meta: dict | None = None) -> dict:
    capture_meta = capture_meta or {}
    technology_counts = {
        "2G": len(parsed.get("bssap", [])),
        "3G": len(parsed.get("ranap", [])) + len(parsed.get("map", [])),
        "LTE/4G": len(parsed.get("s1ap", [])) + len(parsed.get("gtp", [])) + len(parsed.get("nas_eps", [])),
        "5G": len(parsed.get("ngap", [])) + len(parsed.get("pfcp", [])) + len(parsed.get("http", [])) + len(parsed.get("nas_5gs", [])),
        "IMS": len(parsed.get("sip", [])) + len(parsed.get("diameter", [])) + len(parsed.get("inap", [])),
        "Transport": len(parsed.get("tcp", [])) + len(parsed.get("udp", [])) + len(parsed.get("sctp", [])),
        "SCTP": len(parsed.get("sctp", [])),
        "Core Services": len(parsed.get("dns", [])) + len(parsed.get("icmp", [])),
        "HTTPS": len([p for p in parsed.get("http", []) if p.get("tls_type") or p.get("protocol") == "HTTP"]),
    }
    protocol_counts = {
        key.upper(): len(value)
        for key, value in parsed.items()
        if isinstance(value, list) and value
    }
    protocol_breakdown = _build_protocol_breakdown(parsed)
    tcp_issues = sum(1 for p in parsed.get("tcp", []) if p.get("is_failure"))
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
    return {
        "headline": f"{call_type} session",
        "call_type": call_type,
        "a_party": session.get("calling") or session.get("msisdn") or "Unknown",
        "b_party": session.get("called") or "Unknown",
        "protocols": protocols,
        "technologies": technologies,
        "summary_lines": [
            f"Call/session type: {call_type}",
            f"Technologies: {', '.join(technologies) if technologies else 'Unknown'}",
            f"Protocols: {', '.join(protocols) if protocols else 'Unknown'}",
            f"A-party: {session.get('calling') or session.get('msisdn') or 'Unknown'}",
            f"B-party: {session.get('called') or 'Unknown'}",
            f"Flow summary: {session.get('flow_summary') or 'Unavailable'}",
        ],
    }


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


def _extract_trace_parties(parsed: dict, sessions: list, subscriber: str | None = None) -> tuple[str | None, str | None]:
    for packet in parsed.get("sip", []):
        caller = _extract_number(packet.get("from_uri"))
        callee = _extract_number(packet.get("to_uri"))
        if caller or callee:
            return caller or packet.get("src_ip"), callee or packet.get("dst_ip")

    for session in sessions:
        if session.get("calling") or session.get("called"):
            return session.get("calling"), session.get("called")

    if subscriber:
        for packet in parsed.get("diameter", []):
            if packet.get("imsi") == subscriber or packet.get("msisdn"):
                return packet.get("msisdn") or packet.get("src_ip"), packet.get("apn") or packet.get("dst_ip")

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
