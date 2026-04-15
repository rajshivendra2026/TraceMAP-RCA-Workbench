from collections import Counter


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


def build_capture_summary(parsed: dict, sessions: list) -> dict:
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
    expert_findings = _build_expert_findings(
        protocol_counts=protocol_counts,
        technology_counts=technology_counts,
        tcp_issues=tcp_issues,
        failed_sessions=failed_sessions,
        sessions=sessions,
    )

    return {
        "technology_counts": technology_counts,
        "protocol_counts": protocol_counts,
        "rca_distribution": dict(rca_distribution),
        "top_endpoints": endpoint_activity[:6],
        "expert_findings": expert_findings,
        "details": build_trace_details_summary(parsed, sessions, protocol_counts, technology_counts),
        "kpis": {
            "total_sessions": len(sessions),
            "total_packets": total_packets,
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


def build_trace_details_summary(parsed: dict, sessions: list, protocol_counts: dict, technology_counts: dict) -> dict:
    a_party, b_party = _extract_trace_parties(parsed, sessions)
    top_protocols = sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)[:4]
    technologies_seen = [tech for tech, count in technology_counts.items() if count > 0]
    dominant_protocol = top_protocols[0][0] if top_protocols else "UNKNOWN"
    trace_type = _infer_trace_type(protocol_counts, technologies_seen)
    headline = _build_trace_headline(trace_type, top_protocols, technologies_seen)

    return {
        "headline": headline,
        "trace_type": trace_type,
        "a_party": a_party,
        "b_party": b_party,
        "top_protocols": top_protocols,
        "technologies_seen": technologies_seen,
        "summary_lines": [
            f"Primary trace type: {trace_type}",
            f"Technologies observed: {', '.join(technologies_seen) if technologies_seen else 'Unknown'}",
            f"Dominant protocol: {dominant_protocol}",
            f"A-party: {a_party or 'Unknown'}",
            f"B-party: {b_party or 'Unknown'}",
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


def _extract_trace_parties(parsed: dict, sessions: list) -> tuple[str | None, str | None]:
    for session in sessions:
        if session.get("calling") or session.get("called"):
            return session.get("calling"), session.get("called")

    for packet in parsed.get("map", []):
        if packet.get("msisdn") or packet.get("dst_ip"):
            return packet.get("msisdn") or packet.get("src_ip"), packet.get("dst_ip")

    for key in ("sip", "diameter", "s1ap", "ngap", "ranap", "bssap", "http", "dns", "icmp", "nas_eps", "nas_5gs", "tcp", "udp", "sctp"):
        for packet in parsed.get(key, []):
            if packet.get("src_ip") or packet.get("dst_ip"):
                return packet.get("src_ip"), packet.get("dst_ip")

    return None, None


def _infer_trace_type(protocol_counts: dict, technologies_seen: list) -> str:
    if protocol_counts.get("MAP"):
        return "MAP mobility/signalling trace"
    if protocol_counts.get("SIP"):
        return "IMS call trace"
    if protocol_counts.get("NGAP") or protocol_counts.get("PFCP"):
        return "5G signalling trace"
    if protocol_counts.get("S1AP") or protocol_counts.get("GTP"):
        return "LTE/4G signalling trace"
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
