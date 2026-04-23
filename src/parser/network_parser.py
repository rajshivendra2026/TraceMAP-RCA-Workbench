import re
from typing import Optional

from loguru import logger


TECH_BY_PROTOCOL = {
    "BSSAP": "2G",
    "GSM_MAP": "2G/3G",
    "MAP": "2G/3G",
    "RANAP": "3G",
    "S1AP": "LTE/4G",
    "NAS_EPS": "LTE/4G",
    "GTP": "LTE/4G",
    "GTPV2": "LTE/4G",
    "DIAMETER": "IMS",
    "SIP": "IMS",
    "INAP": "IMS/PSTN",
    "NGAP": "5G",
    "NAS_5GS": "5G",
    "HTTP2": "5G",
    "IKEV2": "VoWiFi/ePDG",
    "PFCP": "5G",
    "RADIUS": "AAA",
    "DNS": "Core",
    "ICMP": "Core",
    "SCTP": "Transport",
    "TCP": "Transport",
    "UDP": "Transport",
    "TLS": "HTTPS",
    "HTTP": "HTTP",
}

GTPV2_MESSAGE_NAMES = {
    "1": "Echo Request",
    "2": "Echo Response",
    "32": "Create Session Request",
    "33": "Create Session Response",
    "34": "Modify Bearer Request",
    "35": "Modify Bearer Response",
    "36": "Delete Session Request",
    "37": "Delete Session Response",
    "95": "Create Bearer Request",
    "96": "Create Bearer Response",
    "97": "Update Bearer Request",
    "98": "Update Bearer Response",
    "133": "Forward Relocation Request",
    "134": "Forward Relocation Response",
    "170": "Release Access Bearers Request",
    "171": "Release Access Bearers Response",
}

GTP_CAUSE_NAMES = {
    "16": "Request Accepted",
    "18": "New PDN Type Due To Network Preference",
    "64": "Context Not Found",
    "72": "System Failure",
    "73": "No Resources Available",
    "78": "Missing or Unknown APN",
    "83": "Preferred PDN Type Not Supported",
    "87": "UE Not Responding",
    "89": "Service Not Supported",
    "94": "Request Rejected",
}

PFCP_MESSAGE_NAMES = {
    "1": "Heartbeat Request",
    "2": "Heartbeat Response",
    "5": "Association Setup Request",
    "6": "Association Setup Response",
    "7": "Association Update Request",
    "8": "Association Update Response",
    "9": "Association Release Request",
    "10": "Association Release Response",
    "50": "Session Establishment Request",
    "51": "Session Establishment Response",
    "52": "Session Modification Request",
    "53": "Session Modification Response",
    "54": "Session Deletion Request",
    "55": "Session Deletion Response",
    "56": "Session Report Request",
    "57": "Session Report Response",
}

PFCP_CAUSE_NAMES = {
    "1": "Request Accepted",
    "64": "Request Rejected",
    "65": "Session Context Not Found",
    "66": "Mandatory IE Missing",
    "67": "Conditional IE Missing",
    "68": "Invalid Length",
    "69": "Mandatory IE Incorrect",
    "70": "Invalid Forwarding Policy",
    "71": "Invalid F-TEID Allocation Option",
    "72": "No Established PFCP Association",
    "73": "Rule Creation or Modification Failure",
}

S1AP_PROCEDURE_NAMES = {
    "1": "Handover Resource Allocation",
    "2": "Handover Notification",
    "5": "E-RAB Setup",
    "7": "E-RAB Release",
    "9": "Initial Context Setup",
    "10": "Paging",
    "11": "Downlink NAS Transport",
    "12": "Initial UE Message",
    "13": "Uplink NAS Transport",
    "17": "UE Capability Info Indication",
    "18": "UE Context Release Request",
    "21": "UE Context Release",
    "22": "eNB Status Transfer",
    "23": "MME Status Transfer",
}

NGAP_PROCEDURE_NAMES = {
    "4": "Downlink NAS Transport",
    "12": "Handover Required",
    "13": "Handover Request",
    "14": "Initial Context Setup",
    "15": "Initial UE Message",
    "41": "UE Context Release",
    "42": "UE Context Release Request",
    "44": "UE Radio Capability Info Indication",
    "46": "Uplink NAS Transport",
}

RANAP_PROCEDURE_NAMES = {
    "19": "Relocation Required",
    "20": "Relocation Command",
}

BSSAP_MESSAGE_NAMES = {
    "0x01": "BSSAP Reset",
    "0x04": "BSSAP Clear Command",
    "0x08": "BSSAP Paging",
    "0x09": "BSSAP Unitdata",
}

NAS_EPS_EMM_MESSAGE_NAMES = {
    "0x41": "Attach Request",
    "0x42": "Attach Accept",
    "0x43": "Attach Complete",
    "0x44": "Attach Reject",
    "0x48": "Tracking Area Update Request",
    "0x49": "Tracking Area Update Accept",
    "0x4a": "Tracking Area Update Complete",
    "0x4b": "Tracking Area Update Reject",
    "0x4c": "Extended Service Request",
    "0x4e": "Service Reject",
    "0x50": "Service Request",
    "0x52": "Authentication Response",
    "0x53": "Authentication Failure",
    "0x56": "Identity Response",
}

NAS_EPS_ESM_MESSAGE_NAMES = {
    "0xc1": "Activate Default EPS Bearer Context Request",
    "0xc2": "Activate Default EPS Bearer Context Accept",
    "0xc3": "Activate Default EPS Bearer Context Reject",
    "0xc5": "PDN Connectivity Reject",
    "0xc9": "PDN Connectivity Request",
    "0xcd": "Bearer Resource Command",
    "0xce": "Bearer Resource Failure Indication",
    "0xd0": "Bearer Resource Modification Reject",
}

NAS_5GS_MM_MESSAGE_NAMES = {
    "0x41": "Registration Request",
    "0x42": "Registration Accept",
    "0x43": "Registration Complete",
    "0x44": "Registration Reject",
    "0x4c": "Service Reject",
    "0x56": "Authentication Request",
    "0x57": "Authentication Response",
    "0x5b": "Identity Request",
    "0x5c": "Identity Response",
    "0x5d": "Security Mode Command",
    "0x5e": "Security Mode Complete",
}

NAS_5GS_SM_MESSAGE_NAMES = {
    "0xc1": "PDU Session Establishment Request",
    "0xc2": "PDU Session Establishment Accept",
    "0xc3": "PDU Session Establishment Reject",
}

SUCCESS_CAUSE_CODES = {"0", "16", "18", "128", "REQUEST_ACCEPTED", "DIAMETER_SUCCESS"}
NAS_FAILURE_KEYWORDS = ("REJECT", "FAIL", "DENIED")
RADIUS_CODE_NAMES = {
    "1": "Access-Request",
    "2": "Access-Accept",
    "3": "Access-Reject",
    "4": "Accounting-Request",
    "5": "Accounting-Response",
    "11": "Access-Challenge",
    "40": "Disconnect-Request",
    "41": "Disconnect-ACK",
    "42": "Disconnect-NAK",
    "43": "CoA-Request",
    "44": "CoA-ACK",
    "45": "CoA-NAK",
}
RADIUS_ACCT_STATUS_NAMES = {
    "1": "Start",
    "2": "Stop",
    "3": "Interim-Update",
    "7": "Accounting-On",
    "8": "Accounting-Off",
}
RADIUS_SERVICE_TYPE_NAMES = {
    "1": "Login",
    "2": "Framed",
    "5": "Outbound",
    "8": "Authenticate-Only",
    "10": "Call-Check",
}
IKEV2_EXCHANGE_NAMES = {
    "34": "IKE_SA_INIT",
    "35": "IKE_AUTH",
    "36": "CREATE_CHILD_SA",
    "37": "INFORMATIONAL",
    "38": "IKE_SESSION_RESUME",
}
IKE_NOTIFY_NAMES = {
    "1": "UNSUPPORTED_CRITICAL_PAYLOAD",
    "4": "INVALID_IKE_SPI",
    "5": "INVALID_MAJOR_VERSION",
    "7": "INVALID_SYNTAX",
    "9": "INVALID_MESSAGE_ID",
    "11": "INVALID_SPI",
    "14": "NO_PROPOSAL_CHOSEN",
    "17": "INVALID_KE_PAYLOAD",
    "24": "AUTHENTICATION_FAILED",
    "34": "SINGLE_PAIR_REQUIRED",
    "35": "NO_ADDITIONAL_SAS",
    "36": "INTERNAL_ADDRESS_FAILURE",
    "37": "FAILED_CP_REQUIRED",
    "38": "TS_UNACCEPTABLE",
    "39": "INVALID_SELECTORS",
    "43": "TEMPORARY_FAILURE",
    "44": "CHILD_SA_NOT_FOUND",
    "16388": "NAT_DETECTION_SOURCE_IP",
    "16389": "NAT_DETECTION_DESTINATION_IP",
    "16400": "INITIAL_CONTACT",
}


def parse_network_packets(raw_packets: list, protocol_name: str) -> list:
    packets = []
    skipped = 0

    for raw in raw_packets:
        packet = parse_network_packet(raw, protocol_name)
        if packet:
            packets.append(packet)
        else:
            skipped += 1

    logger.info(f"{protocol_name} parser: {len(packets)} valid, {skipped} skipped")
    return packets


def parse_network_packet(raw: dict, protocol_name: str) -> Optional[dict]:
    timestamp = _to_float(_get(raw, "frame.time_epoch"))
    frame_number = _to_int(_get(raw, "frame.number"))
    src_ip = _clean_text(
        _get(
            raw,
            "ip.src",
            "ipv6.src",
            "sccp.calling.digits",
            "e164.msisdn",
            "e212.imsi",
            "sccp.calling.ssn",
            "mtp3.network_indicator",
        )
    )
    dst_ip = _clean_text(
        _get(
            raw,
            "ip.dst",
            "ipv6.dst",
            "sccp.called.digits",
            "sccp.called.ssn",
            "mtp3.network_indicator",
        )
    )
    src_port = _to_int(_get(raw, "tcp.srcport", "udp.srcport", "sctp.srcport"))
    dst_port = _to_int(_get(raw, "tcp.dstport", "udp.dstport", "sctp.dstport"))
    protocol = protocol_name.upper()
    transport = _detect_transport(raw)
    stream_id = _clean_text(_get(raw, "tcp.stream", "udp.stream", "sctp.stream"))
    pfcp_message_type = _clean_text(_get(raw, "pfcp.msg_type", "pfcp.message_type"))
    pfcp_seqno = _clean_text(_get(raw, "pfcp.seqno"))
    pfcp_seid = _clean_text(_get(raw, "pfcp.seid"))
    pfcp_node_id = _clean_text(_get(raw, "pfcp.node_id_ipv4", "pfcp.node_id_ipv6", "pfcp.node_id_fqdn"))
    s1ap_mme_ue_id = _clean_text(_get(raw, "s1ap.MME_UE_S1AP_ID"))
    s1ap_enb_ue_id = _clean_text(_get(raw, "s1ap.ENB_UE_S1AP_ID"))
    ngap_amf_ue_id = _clean_text(_get(raw, "ngap.AMF_UE_NGAP_ID"))
    ngap_ran_ue_id = _clean_text(_get(raw, "ngap.RAN_UE_NGAP_ID"))
    transaction_id = _clean_text(
        _get(
            raw,
            "s1ap.MME_UE_S1AP_ID",
            "s1ap.ENB_UE_S1AP_ID",
            "ngap.AMF_UE_NGAP_ID",
            "ngap.RAN_UE_NGAP_ID",
            "tcap.tid",
            "gtp.tid",
            "pfcp.seid",
            "pfcp.seqno",
            "dns.id",
            "radius.Acct_Session_Id",
            "radius.id",
            "e164.msisdn",
            "e212.imsi",
        )
    )
    method = _clean_text(_get(raw, "http.request.method", "http2.headers.method"))
    status_code = _clean_text(_get(raw, "http.response.code", "http2.headers.status"))
    uri = _clean_text(_get(raw, "http.request.uri", "http2.headers.path"))
    radius_code = _clean_text(_get(raw, "radius.code"))
    radius_id = _clean_text(_get(raw, "radius.id"))
    radius_user_name = _clean_text(_get(raw, "radius.User_Name"))
    radius_calling_station = _clean_text(_get(raw, "radius.Calling_Station_Id"))
    radius_called_station = _clean_text(_get(raw, "radius.Called_Station_Id"))
    radius_acct_status = _clean_text(_get(raw, "radius.Acct_Status_Type"))
    radius_framed_ip = _clean_text(_get(raw, "radius.Framed_IP_Address"))
    radius_acct_session_id = _clean_text(_get(raw, "radius.Acct_Session_Id"))
    radius_nas_identifier = _clean_text(_get(raw, "radius.NAS_Identifier"))
    radius_service_type = _clean_text(_get(raw, "radius.Service_Type"))
    radius_reply_message = _clean_text(_get(raw, "radius.Reply_Message"))
    radius_state = _clean_text(_get(raw, "radius.State"))
    radius_class = _clean_text(_get(raw, "radius.Class"))
    if protocol == "RADIUS" and not status_code:
        status_code = radius_code
    host = _clean_text(_get(raw, "http.host", "http2.headers.authority"))
    ws_info = _clean_text(_get(raw, "_ws.col.info"))
    sbi_context = _extract_sbi_context(raw, uri, host, ws_info) if protocol == "HTTP" else {}
    ike_exchange_type = _clean_text(_get(raw, "ikev2.exchange_type", "isakmp.exchangetype"))
    ike_notify_type = _clean_text(_get(raw, "isakmp.notify.msgtype"))
    ike_inner_ip = _clean_text(
        _get(
            raw,
            "isakmp.cfg.attr.internal_ip4_address",
            "isakmp.cfg.attr.internal_ip6_address",
            "isakmp.cfg.attr.internal_ip6_prefix_ip",
            "isakmp.ts.start_ipv4",
            "isakmp.ts.start_ipv6",
            "isakmp.ts.end_ipv4",
            "isakmp.ts.end_ipv6",
            "ikev2.cfg.attr.internal_ip4_address",
            "ikev2.cfg.attr.internal_ip6_address",
            "ikev2.traffic_selector.initiator_ts_ipv4",
            "ikev2.traffic_selector.initiator_ts_ipv6",
            "ikev2.traffic_selector.responder_ts_ipv4",
            "ikev2.traffic_selector.responder_ts_ipv6",
        )
    )
    ike_identity = _clean_text(
        _get(
            raw,
            "ikev2.idi",
            "ikev2.idr",
            "isakmp.idir_data",
            "isakmp.id.data.user_fqdn",
            "isakmp.id.data.fqdn",
            "isakmp.id.data.ipv4_addr",
            "isakmp.id.data.ipv6_addr",
            "isakmp.id.data.key_id",
        )
    )
    dns_query = _clean_text(_get(raw, "dns.qry.name", "dns.resp.name"))
    dns_rcode = _clean_text(_get(raw, "dns.flags.rcode"))
    dns_answer = _clean_text(_get(raw, "dns.a", "dns.aaaa", "dns.cname"))
    icmp_type = _clean_text(_get(raw, "icmp.type", "icmpv6.type"))
    icmp_code = _clean_text(_get(raw, "icmp.code", "icmpv6.code"))
    nas_eps_mm = _clean_text(_get(raw, "nas-eps.nas_msg_emm_type", "nas-eps.emm.message_type", "nas_eps.nas_msg_emm_type", "nas_eps.emm.message_type"))
    nas_eps_sm = _clean_text(_get(raw, "nas-eps.nas_msg_esm_type", "nas-eps.esm.message_type", "nas_eps.nas_msg_esm_type", "nas_eps.esm.message_type"))
    nas_5gs_mm = _clean_text(_get(raw, "nas-5gs.mm.message_type", "nas_5gs.mm.message_type"))
    nas_5gs_sm = _clean_text(_get(raw, "nas-5gs.sm.message_type", "nas_5gs.sm.message_type"))
    gtp_tid = _clean_text(_get(raw, "gtp.tid"))
    gtp_teid = _clean_text(
        _get(
            raw,
            "gtpv2.teid",
            "gtp.teid",
            "gtpv2.teid_c",
            "gtp.teid_cp",
            "gtp.uplink_teid_cp",
            "gtp.teid_data",
            "gtp.uplink_teid_data",
            "gtpv2.sgw_s1u_teid",
        )
    )
    gtp_f_teid = _clean_text(_get(raw, "gtpv2.f_teid_gre_key"))
    gtp_f_teid_ip = _clean_text(_get(raw, "gtpv2.f_teid_ipv4", "gtpv2.f_teid_ipv6"))
    gtp_subscriber_ip = _clean_text(
        _get(
            raw,
            "gtpv2.pdn_addr_and_prefix.ipv4",
            "gtpv2.pdn_addr_and_prefix.ipv6",
            "gtp.user_ipv4",
            "gtp.user_ipv6",
            "gtp.pdp_address.ipv4",
            "gtp.pdp_address.ipv6",
        )
    )
    gtp_apn = _clean_text(_get(raw, "gtpv2.apn", "gtp.apn"))
    gtp_bearer_id = _clean_text(_get(raw, "gtpv2.ebi", "gtpv2.eps_bearer_id_number"))
    gtpv2_message_type = _clean_text(_get(raw, "gtpv2.message_type"))
    gtp_message_type = _clean_text(_get(raw, "gtp.message_type"))
    gtp_cause = _clean_text(_get(raw, "gtpv2.cause_value", "gtpv2.cause"))
    gtp_imsi = _clean_text(_get(raw, "gtpv2.imsi"))
    msisdn = _clean_text(
        _get(
            raw,
            "gsm_map.msisdn",
            "sccp.calling.digits",
            "sccp.called.digits",
            "e164.msisdn",
            "gsm_map.address.digits",
            "gsm_map.tbcd_digits",
        )
    )
    imsi = _clean_text(_get(raw, "gsm_map.imsi", "e212.imsi", "gtpv2.imsi")) or sbi_context.get("imsi")
    msisdn = msisdn or sbi_context.get("msisdn")
    procedure = _clean_text(
        _get(
            raw,
            "gtpv2.message_type",
            "gtp.message_type",
            "s1ap.procedureCode",
            "ngap.procedureCode",
            "ranap.procedureCode",
            "bssap.pdu_type",
            "bssap.message_type",
            "pfcp.msg_type",
            "pfcp.message_type",
            "sctp.ppid",
            "sctp.chunk_type",
            "dns.qry.type",
            "nas-eps.emm.message_type",
            "nas-eps.esm.message_type",
            "nas-5gs.mm.message_type",
            "nas-5gs.sm.message_type",
            "nas_eps.emm.message_type",
            "nas_eps.esm.message_type",
            "nas_5gs.mm.message_type",
            "nas_5gs.sm.message_type",
        )
    )
    cause_code = _clean_text(
        _get(
            raw,
            "gtpv2.cause_value",
            "gtpv2.cause",
            "s1ap.CauseRadioNetwork",
            "ngap.Cause",
            "ranap.Cause",
            "pfcp.cause",
            "dns.flags.rcode",
            "isakmp.notify.msgtype",
            "nas-eps.emm.cause",
            "nas-eps.esm.cause",
            "nas-5gs.mm.5gmm_cause",
            "nas-5gs.sm.cause",
            "nas_eps.emm.cause",
            "nas_eps.esm.cause",
            "nas_5gs.mm.cause",
            "nas_5gs.sm.cause",
        )
    )
    tls_type = _clean_text(_get(raw, "tls.handshake.type"))
    retransmission = bool(_clean_text(_get(raw, "tcp.analysis.retransmission")))
    fast_retransmission = bool(_clean_text(_get(raw, "tcp.analysis.fast_retransmission")))
    duplicate_ack = bool(_clean_text(_get(raw, "tcp.analysis.duplicate_ack")))
    ack_lost_segment = bool(_clean_text(_get(raw, "tcp.analysis.ack_lost_segment")))
    lost_segment = bool(_clean_text(_get(raw, "tcp.analysis.lost_segment")))
    reset = str(_clean_text(_get(raw, "tcp.flags.reset"))).strip() in {"1", "true", "True"}

    if frame_number is None and timestamp is None and not (src_ip or dst_ip):
        return None

    if protocol == "GTP":
        transaction_id = _first_non_null(transaction_id, gtp_tid, gtp_teid, gtp_f_teid, gtp_subscriber_ip, gtp_imsi)
    if protocol == "HTTP":
        transaction_id = _first_non_null(transaction_id, sbi_context.get("supi"), sbi_context.get("gpsi"), stream_id)
    if protocol == "IKEV2":
        transaction_id = _first_non_null(transaction_id, ike_identity, ike_inner_ip, stream_id)

    message = _first_non_null(
        _format_radius_message(radius_code, radius_acct_status, radius_service_type, radius_reply_message),
        _format_http_message(method, status_code, uri),
        _format_dns_message(dns_query, dns_answer, dns_rcode),
        _format_icmp_message(icmp_type, icmp_code),
        _format_sctp_message(protocol, _clean_text(_get(raw, "sctp.chunk_type")), _clean_text(_get(raw, "sctp.ppid"))),
        _format_pfcp_message(pfcp_message_type, cause_code),
        _format_gtp_message(gtpv2_message_type, gtp_message_type, gtp_cause),
        _format_ike_message(protocol, ike_exchange_type, ike_notify_type),
        _format_ws_info_message(protocol, ws_info),
        _format_access_message(protocol, procedure),
        _format_nas_message(protocol, nas_eps_mm, nas_eps_sm, nas_5gs_mm, nas_5gs_sm, cause_code),
        procedure,
        tls_type,
        cause_code,
        protocol,
    )

    packet = {
        "frame_number": frame_number,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "technology": _derive_technology(protocol, tls_type, uri, host, sbi_context.get("sbi_service")),
        "transport": transport,
        "stream_id": stream_id,
        "transaction_id": transaction_id,
        "gtp.tid": gtp_tid,
        "gtp.teid": gtp_teid,
        "gtp.f_teid": gtp_f_teid,
        "gtp.f_teid_ip": gtp_f_teid_ip,
        "gtp.subscriber_ip": gtp_subscriber_ip,
        "gtp.apn": gtp_apn.lower() if gtp_apn else None,
        "gtp.bearer_id": gtp_bearer_id,
        "gtpv2.imsi": gtp_imsi,
        "gtpv2.message_type": gtpv2_message_type,
        "gtp.message_type": gtp_message_type,
        "gtpv2.cause_value": gtp_cause,
        "pfcp.message_type": pfcp_message_type,
        "pfcp.seqno": pfcp_seqno,
        "pfcp.seid": pfcp_seid,
        "pfcp.node_id": pfcp_node_id,
        "s1ap_mme_ue_id": s1ap_mme_ue_id,
        "s1ap_enb_ue_id": s1ap_enb_ue_id,
        "ngap_amf_ue_id": ngap_amf_ue_id,
        "ngap_ran_ue_id": ngap_ran_ue_id,
        "message": message,
        "method": method,
        "status_code": status_code,
        "host": host,
        "uri": uri,
        "sbi_service": sbi_context.get("sbi_service"),
        "supi": sbi_context.get("supi"),
        "gpsi": sbi_context.get("gpsi"),
        "sbi_payload_hint": sbi_context.get("payload_hint"),
        "ike_exchange_type": ike_exchange_type,
        "ike_notify_type": ike_notify_type,
        "ike_inner_ip": ike_inner_ip,
        "ike_identity": ike_identity,
        "radius_code": radius_code,
        "radius_id": radius_id,
        "radius_user_name": radius_user_name,
        "radius_calling_station_id": radius_calling_station,
        "radius_called_station_id": radius_called_station,
        "radius_acct_status_type": radius_acct_status,
        "radius_framed_ip": radius_framed_ip,
        "radius_acct_session_id": radius_acct_session_id,
        "radius_nas_identifier": radius_nas_identifier,
        "radius_service_type": radius_service_type,
        "radius_reply_message": radius_reply_message,
        "radius_state": radius_state,
        "radius_class": radius_class,
        "dns_query": dns_query,
        "dns_answer": dns_answer,
        "dns_rcode": dns_rcode,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "nas_eps_mm": nas_eps_mm,
        "nas_eps_sm": nas_eps_sm,
        "nas_5gs_mm": nas_5gs_mm,
        "nas_5gs_sm": nas_5gs_sm,
        "msisdn": msisdn,
        "imsi": imsi,
        "procedure": procedure,
        "cause_code": cause_code,
        "tls_type": tls_type,
        "ws_info": ws_info,
        "retransmission": retransmission,
        "fast_retransmission": fast_retransmission,
        "duplicate_ack": duplicate_ack,
        "ack_lost_segment": ack_lost_segment,
        "lost_segment": lost_segment,
        "reset": reset,
        "is_failure": _is_failure(protocol, message, status_code, cause_code, retransmission, reset, icmp_type, icmp_code),
    }
    return packet


def _derive_technology(
    protocol: str,
    tls_type: Optional[str],
    uri: Optional[str] = None,
    host: Optional[str] = None,
    sbi_service: Optional[str] = None,
) -> str:
    if protocol == "HTTP" and (sbi_service or _looks_like_sbi_text(uri) or _looks_like_sbi_text(host)):
        return "5G"
    if protocol == "HTTP" and tls_type:
        return "HTTPS"
    return TECH_BY_PROTOCOL.get(protocol, "Core")


def _detect_transport(raw: dict) -> str:
    if _get(raw, "tcp.stream") is not None:
        return "TCP"
    if _get(raw, "udp.stream") is not None:
        return "UDP"
    if _get(raw, "sctp.stream") is not None:
        return "SCTP"
    return "IP"


def _extract_sbi_context(
    raw: dict,
    uri: Optional[str],
    host: Optional[str],
    ws_info: Optional[str],
) -> dict[str, Optional[str]]:
    payload = _joined_text(
        [
            uri,
            host,
            ws_info,
            *_values(
                raw,
                "http.file_data",
                "http2.data.data",
                "json.key",
                "json.value.string",
                "json.value.number",
                "json.member_with_value",
            ),
        ]
    )
    supi = _extract_supi(payload)
    gpsi = _extract_gpsi(payload)
    return {
        "sbi_service": _extract_sbi_service(payload),
        "supi": supi,
        "gpsi": gpsi,
        "imsi": _digits_from_prefixed_identity(supi, "imsi"),
        "msisdn": _digits_from_prefixed_identity(gpsi, "msisdn"),
        "payload_hint": _trim_payload_hint(payload),
    }


def _extract_supi(text: str) -> Optional[str]:
    if not text:
        return None
    patterns = (
        r"\b(?:supi|supiOrSuci|ueId|imsi)[\"'\s:=/-]*(?:imsi-)?(\d{14,16})\b",
        r"\bimsi-(\d{14,16})\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return f"imsi-{match.group(1)}"
    return None


def _extract_gpsi(text: str) -> Optional[str]:
    if not text:
        return None
    patterns = (
        r"\b(?:gpsi|msisdn)[\"'\s:=/-]*(?:msisdn-)?(\d{6,15})\b",
        r"\bmsisdn-(\d{6,15})\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return f"msisdn-{match.group(1)}"
    return None


def _extract_sbi_service(text: str) -> Optional[str]:
    if not text:
        return None
    match = re.search(r"\b(n[a-z0-9]+(?:-[a-z0-9]+)*)\b", text, flags=re.IGNORECASE)
    if not match:
        return None
    service = match.group(1).lower()
    if service.startswith(("namf", "nsmf", "nudm", "nrf", "nssf", "ausf", "nausf", "npcf", "nchf", "nef", "nnef", "bsf", "nbsf")):
        return service
    return None


def _digits_from_prefixed_identity(value: Optional[str], prefix: str) -> Optional[str]:
    if not value:
        return None
    expected = f"{prefix}-"
    if str(value).lower().startswith(expected):
        digits = str(value)[len(expected):]
        return digits if digits.isdigit() else None
    return None


def _trim_payload_hint(text: str) -> Optional[str]:
    if not text:
        return None
    compact = re.sub(r"\s+", " ", text).strip()
    return compact[:240] if compact else None


def _looks_like_sbi_text(value: Optional[str]) -> bool:
    if not value:
        return False
    return _extract_sbi_service(str(value)) is not None


def _joined_text(values: list[Optional[str]]) -> str:
    return " ".join(str(value) for value in values if value)


def _values(raw: dict, *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = raw.get(key)
        if value is None or value == "":
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            text = _clean_text(item)
            if not text:
                continue
            values.append(text)
            decoded = _decode_hex_payload(text)
            if decoded:
                values.append(decoded)
    return values


def _decode_hex_payload(value: str) -> Optional[str]:
    text = str(value or "").strip()
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:?){8,}", text):
        return None
    try:
        raw = bytes.fromhex(text.replace(":", ""))
        decoded = raw.decode("utf-8", errors="ignore").strip()
    except ValueError:
        return None
    return decoded or None


def _format_http_message(method: Optional[str], status_code: Optional[str], uri: Optional[str]) -> Optional[str]:
    if method:
        return f"{method} {uri or ''}".strip()
    if status_code:
        return f"HTTP {status_code}"
    return None


def _format_radius_message(
    radius_code: Optional[str],
    acct_status: Optional[str],
    service_type: Optional[str],
    reply_message: Optional[str],
) -> Optional[str]:
    if not radius_code:
        return None
    message = RADIUS_CODE_NAMES.get(str(radius_code), f"RADIUS code {radius_code}")
    details = []
    if acct_status:
        details.append(RADIUS_ACCT_STATUS_NAMES.get(str(acct_status), f"Acct {acct_status}"))
    if service_type:
        details.append(RADIUS_SERVICE_TYPE_NAMES.get(str(service_type), f"Service {service_type}"))
    if reply_message:
        details.append(reply_message)
    if details:
        return f"{message} ({'; '.join(details)})"
    return message


def _format_dns_message(query: Optional[str], answer: Optional[str], rcode: Optional[str]) -> Optional[str]:
    if query and answer:
        return f"DNS {query} -> {answer}"
    if query:
        suffix = f" rcode={rcode}" if rcode not in (None, "", "0") else ""
        return f"DNS {query}{suffix}"
    return None


def _format_icmp_message(icmp_type: Optional[str], icmp_code: Optional[str]) -> Optional[str]:
    if icmp_type:
        if icmp_code:
            return f"ICMP type {icmp_type} code {icmp_code}"
        return f"ICMP type {icmp_type}"
    return None


def _format_gtp_message(
    gtpv2_message_type: Optional[str],
    gtp_message_type: Optional[str],
    cause_code: Optional[str],
) -> Optional[str]:
    message_type = gtpv2_message_type or gtp_message_type
    if not message_type:
        return None
    message_name = GTPV2_MESSAGE_NAMES.get(str(message_type), f"GTPv2 {message_type}")
    if cause_code:
        cause_name = GTP_CAUSE_NAMES.get(str(cause_code), f"Cause {cause_code}")
        return f"{message_name} ({cause_name})"
    return message_name


def _format_pfcp_message(
    pfcp_message_type: Optional[str],
    cause_code: Optional[str],
) -> Optional[str]:
    if not pfcp_message_type:
        return None
    message_name = PFCP_MESSAGE_NAMES.get(str(pfcp_message_type), f"PFCP {pfcp_message_type}")
    if cause_code:
        cause_name = PFCP_CAUSE_NAMES.get(str(cause_code), f"Cause {cause_code}")
        return f"{message_name} ({cause_name})"
    return message_name


def _format_ike_message(
    protocol: str,
    exchange_type: Optional[str],
    notify_type: Optional[str],
) -> Optional[str]:
    if protocol != "IKEV2":
        return None
    exchange = IKEV2_EXCHANGE_NAMES.get(str(exchange_type), f"IKE exchange {exchange_type}") if exchange_type else "IKEv2"
    if notify_type:
        notify = IKE_NOTIFY_NAMES.get(str(notify_type), f"Notify {notify_type}")
        return f"{exchange} ({notify})"
    return exchange


def _format_access_message(protocol: str, procedure: Optional[str]) -> Optional[str]:
    if not procedure:
        return None
    mapping = None
    if protocol == "S1AP":
        mapping = S1AP_PROCEDURE_NAMES
    elif protocol == "NGAP":
        mapping = NGAP_PROCEDURE_NAMES
    elif protocol == "RANAP":
        mapping = RANAP_PROCEDURE_NAMES
    elif protocol == "BSSAP":
        mapping = BSSAP_MESSAGE_NAMES
    if not mapping:
        return None
    return mapping.get(str(procedure), f"{protocol} procedure {procedure}")


def _format_ws_info_message(protocol: str, ws_info: Optional[str]) -> Optional[str]:
    if not ws_info or protocol not in {"MAP", "BSSAP", "RANAP", "NGAP", "S1AP"}:
        return None
    text = " ".join(str(ws_info).split())
    if not text:
        return None
    if protocol == "MAP":
        text = text.replace("returnResultLast", "result")
        text = text.replace("returnError", "error")
        text = text.replace("invoke", "").strip()
        if text:
            return f"MAP {text}"
    if protocol in {"NGAP", "S1AP"}:
        segments = [segment.strip() for segment in text.split(",") if segment.strip()]
        informative = [
            segment for segment in segments
            if not segment.upper().startswith("SACK")
            and not segment.upper().startswith("DATA")
            and "Arwnd=" not in segment
            and "Ack=" not in segment
        ]
        if informative:
            return informative[-1]
        return None
    return text


def _format_sctp_message(protocol: str, chunk_type: Optional[str], ppid: Optional[str]) -> Optional[str]:
    if protocol != "SCTP":
        return None
    chunk_name = {
        "0": "DATA",
        "1": "INIT",
        "2": "INIT_ACK",
        "3": "SACK",
        "4": "HEARTBEAT",
        "5": "HEARTBEAT_ACK",
        "6": "ABORT",
        "7": "SHUTDOWN",
        "8": "SHUTDOWN_ACK",
        "9": "ERROR",
        "10": "COOKIE_ECHO",
        "11": "COOKIE_ACK",
        "14": "SHUTDOWN_COMPLETE",
    }.get(str(chunk_type), chunk_type)
    if chunk_name and ppid:
        return f"{chunk_name} ppid={ppid}"
    if ppid:
        return f"DATA ppid={ppid}"
    return chunk_name


def _format_nas_message(
    protocol: str,
    nas_eps_mm: Optional[str],
    nas_eps_sm: Optional[str],
    nas_5gs_mm: Optional[str],
    nas_5gs_sm: Optional[str],
    cause_code: Optional[str],
) -> Optional[str]:
    if protocol == "NAS_EPS":
        message = NAS_EPS_EMM_MESSAGE_NAMES.get(str(nas_eps_mm), nas_eps_mm) or NAS_EPS_ESM_MESSAGE_NAMES.get(str(nas_eps_sm), nas_eps_sm)
    elif protocol == "NAS_5GS":
        message = NAS_5GS_MM_MESSAGE_NAMES.get(str(nas_5gs_mm), nas_5gs_mm) or NAS_5GS_SM_MESSAGE_NAMES.get(str(nas_5gs_sm), nas_5gs_sm)
    else:
        return None
    if not message:
        return None
    suffix = f" cause={cause_code}" if cause_code else ""
    return f"{protocol} {message}{suffix}"


def _is_failure(
    protocol: str,
    message: Optional[str],
    status_code: Optional[str],
    cause_code: Optional[str],
    retransmission: bool,
    reset: bool,
    icmp_type: Optional[str],
    icmp_code: Optional[str],
) -> bool:
    if protocol in {"MAP", "RANAP", "BSSAP"} and message:
        upper = str(message).upper()
        return any(marker in upper for marker in ("REJECT", "ERROR", "FAIL", "ABORT", "DENIED"))
    if protocol in {"HTTP", "HTTP2"} and status_code:
        return str(status_code).startswith(("4", "5"))
    if protocol == "DNS":
        return bool(cause_code and str(cause_code) not in {"0", "NOERROR"})
    if protocol == "ICMP":
        return str(icmp_type or "") in {"3", "11", "1"} or str(icmp_code or "") not in {"", "0"}
    if protocol == "RADIUS":
        code = str(status_code or "").strip()
        upper_message = str(message or "").upper()
        if code in {"3", "42", "45"}:
            return True
        if any(marker in upper_message for marker in ("REJECT", "NAK", "DENIED")):
            return True
        return False
    if protocol in {"TCP", "UDP"}:
        return retransmission or reset
    if protocol == "NAS_EPS":
        upper_message = str(message or "").upper()
        if any(keyword in upper_message for keyword in NAS_FAILURE_KEYWORDS):
            return True
        return bool(cause_code and str(cause_code) not in SUCCESS_CAUSE_CODES)
    if protocol == "NAS_5GS":
        upper_message = str(message or "").upper()
        if any(keyword in upper_message for keyword in NAS_FAILURE_KEYWORDS):
            return True
        return bool(cause_code and str(cause_code) not in SUCCESS_CAUSE_CODES)
    if protocol == "GTP":
        return bool(cause_code and str(cause_code) not in SUCCESS_CAUSE_CODES)
    if protocol == "PFCP":
        if cause_code:
            return str(cause_code) != "1"
        upper = str(message or "").upper()
        return any(marker in upper for marker in ("REJECT", "NOT FOUND", "FAIL", "MISSING", "ERROR"))
    if protocol == "IKEV2":
        if cause_code:
            try:
                return 0 < int(str(cause_code)) < 16384
            except ValueError:
                pass
        upper = str(message or "").upper()
        return any(marker in upper for marker in ("FAIL", "INVALID", "UNSUPPORTED", "UNACCEPTABLE", "NOT_FOUND"))
    if cause_code and str(cause_code) not in SUCCESS_CAUSE_CODES:
        return True
    return False


def _first_non_null(*values):
    for value in values:
        if value not in (None, ""):
            return value
    return None


def _clean_text(value: Optional[object]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _to_int(value: Optional[object]) -> Optional[int]:
    text = _clean_text(value)
    if not text:
        return None
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _to_float(value: Optional[object]) -> Optional[float]:
    text = _clean_text(value)
    if not text:
        return None
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def _get(d: dict, *keys):
    for key in keys:
        value = d.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, list):
            values = [str(v).strip() for v in value if str(v).strip()]
            if not values:
                continue
            return values[0]
        return value
    return None
