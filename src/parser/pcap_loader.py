# src/parser/pcap_loader.py
"""
PCAP Loader — orchestrates tshark extraction for all protocols.

Changes from v1
───────────────
1. All tshark calls go through TSharkRunner (abstracted, testable).
   No subprocess calls in this file. Pass runner=MockRunner() in tests.

2. All configuration (filters, output dirs) from config.yaml via cfg().
   No hardcoded strings.

3. Extra Diameter fields added:
     - diameter.CC-Request-Number   (tracks request sequence in a session)
     - diameter.Rating-Group        (service being charged)
     - diameter.Granted-Service-Unit (quota granted by OCS)
     - diameter.Used-Service-Unit    (actual usage reported)
   These are needed for full Diameter session reconstruction in the GUI.

4. Added ipv6.src / ipv6.dst to SIP fields — your Trace-05.pcap
   uses IPv6 transport and these fields carry the real IPs.

5. save_parsed() output directory from config.yaml data.parsed.
"""

import json
import os
from pathlib import Path
from loguru import logger

from src.config import cfg, cfg_path
from src.parser.tshark_runner   import TSharkParseError, TSharkRunner
from src.parser.sip_parser      import parse_sip_packets
from src.parser.diameter_parser import parse_diameter_packets
from src.parser.inap_parser     import parse_inap_packets
from src.parser.network_parser  import parse_network_packets


# ══════════════════════════════════════════════════════════════
#  FIELD LISTS
#  Each list defines exactly which tshark fields to extract
#  per protocol. Only listed fields appear in the output dicts.
#  Add fields here if you need more data in downstream modules.
# ══════════════════════════════════════════════════════════════

SIP_FIELDS = [
    # Frame metadata
    "frame.number",
    "frame.time_epoch",

    # Network layer
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",

    # SIP core fields (SAFE SET)
    "sip.Call-ID",
    "sip.Method",
    "sip.Status-Code",

    # Optional but VALID
    "sip.From",
    "sip.To",
    "sip.CSeq",
    "sip.Via",
    "sip.Contact",
    "sip.Reason",

    # Request/Response lines
    "sip.Request-Line",
    "sip.Status-Line",
    "sip.r-uri",
]

DIAMETER_FIELDS = [
    # Frame metadata
    "frame.number",
    "frame.time_epoch",

    # Network layer
    "ip.src",
    "ip.dst",

    # Diameter session identity
    "diameter.Session-Id",        # primary correlation key
    "diameter.Origin-Host",
    "diameter.Origin-Realm",
    "diameter.Destination-Host",
    "diameter.Destination-Realm",

    # Command
    "diameter.cmd.code",          # 272 = CCR/CCA (Ro), 302 = LIR/LIA (Cx)
    "diameter.flags.request",     # "True" = request, "False" = answer

    # Result
    "diameter.Result-Code",       # 2001 = SUCCESS, 5003 = AUTH_REJECTED etc
    "diameter.Experimental-Result-Code",  # vendor-specific result codes
    "diameter.Vendor-Id",
    "diameter.Auth-Application-Id",

    # Credit-Control specific (Ro interface — online charging)
    "diameter.CC-Request-Type",   # 1=INITIAL, 2=UPDATE, 3=TERMINATION, 4=EVENT
    "diameter.CC-Request-Number", # sequence number within a session (added v2)

    # Subscriber identity — CRITICAL for SIP ↔ Diameter correlation
    # Your traces show this as a list: [IMSI, MSISDN]
    "diameter.Subscription-Id-Data",
    "diameter.Subscription-Id-Type",
    "diameter.User-Name",
    "diameter.MSISDN",
    "e164.msisdn",
    "e212.imsi",
    "diameter.Framed-IP-Address",
    "diameter.Called-Station-Id",

    # Service information (added v2 — needed for Diameter Detail tab)
    "diameter.Rating-Group",        # which service is being charged
    "diameter.Service-Identifier",  # sub-service identifier

    # Quota (added v2 — shows what OCS granted/used)
    "diameter.Granted-Service-Unit",
    "diameter.Used-Service-Unit",
]

INAP_FIELDS = [
    # Frame metadata
    "frame.number",
    "frame.time_epoch",

    # Network layer
    "ip.src",
    "ip.dst",

    # TCAP transaction
    "tcap.tid",
    "tcap.ansi_param",

    # INAP operation
    "inap.opcode",
    "inap.serviceKey",

    # Subscriber numbers
    "inap.callingPartyNumber",
    "inap.calledPartyNumber",

    # Failure indicator
    "inap.cause_indicator",
]

GTP_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "gtp.tid",
    "gtp.teid",
    "gtp.teid_cp",
    "gtp.uplink_teid_cp",
    "gtp.teid_data",
    "gtp.uplink_teid_data",
    "gtp.message_type",
    "gtp.user_ipv4",
    "gtp.user_ipv6",
    "gtp.pdp_address.ipv4",
    "gtp.pdp_address.ipv6",
    "gtp.apn",
    "gtpv2.message_type",
    "gtpv2.teid",
    "gtpv2.teid_c",
    "gtpv2.f_teid_gre_key",
    "gtpv2.f_teid_ipv4",
    "gtpv2.f_teid_ipv6",
    "gtpv2.pdn_addr_and_prefix.ipv4",
    "gtpv2.pdn_addr_and_prefix.ipv6",
    "gtpv2.apn",
    "gtpv2.ebi",
    "gtpv2.sgw_s1u_teid",
    "gtpv2.imsi",
    "gtpv2.cause_value",
    "gtpv2.cause",
]

S1AP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "sctp.stream",
    "s1ap.procedureCode", "s1ap.MME_UE_S1AP_ID", "s1ap.ENB_UE_S1AP_ID",
    "s1ap.CauseRadioNetwork", "nas-eps.emm.message_type", "nas-eps.esm.message_type",
    "nas-eps.nas_msg_emm_type", "nas-eps.nas_msg_esm_type",
]

NGAP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "sctp.stream",
    "ngap.procedureCode", "ngap.AMF_UE_NGAP_ID", "ngap.RAN_UE_NGAP_ID",
    "ngap.Cause", "nas-5gs.mm.message_type", "nas-5gs.sm.message_type",
]

RANAP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "sctp.stream",
    "ranap.procedureCode", "ranap.Cause", "tcap.tid", "_ws.col.info",
]

BSSAP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
    "bssap.message_type", "bssap.pdu_type", "bssap.Gs_cause", "tcap.tid", "_ws.col.info",
]

MAP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcap.tid",
    "_ws.col.info",
    "sccp.calling.digits", "sccp.called.digits",
    "sccp.calling.ssn", "sccp.called.ssn",
    "mtp3.network_indicator", "e164.msisdn", "e212.imsi",
    "gsm_map.msisdn", "gsm_map.imsi", "gsm_map.address.digits", "gsm_map.tbcd_digits",
]

HTTP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.stream",
    "tcp.srcport", "tcp.dstport", "http.request.method", "http.request.uri",
    "http.response.code", "http.host", "http2.headers.method", "http2.headers.path",
    "http2.headers.status", "http2.headers.authority", "tls.handshake.type",
    "http.file_data", "http2.data.data", "json.key", "json.value.string",
    "json.value.number", "json.member_with_value", "_ws.col.info",
]

IKEV2_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "udp.stream", "udp.srcport", "udp.dstport", "isakmp.exchangetype",
    "isakmp.messageid", "isakmp.ispi", "isakmp.rspi", "isakmp.notify.msgtype",
    "isakmp.idir_data", "isakmp.id.data.fqdn", "isakmp.id.data.user_fqdn",
    "isakmp.id.data.ipv4_addr", "isakmp.id.data.ipv6_addr", "isakmp.id.data.key_id",
    "isakmp.cfg.attr.internal_ip4_address", "isakmp.cfg.attr.internal_ip6_address",
    "isakmp.cfg.attr.internal_ip6_prefix_ip", "isakmp.cfg.attr.internal_ip6_prefix_length",
    "isakmp.cfg.attr.p_cscf_ip4_address", "isakmp.cfg.attr.p_cscf_ip6_address",
    "isakmp.ts.start_ipv4", "isakmp.ts.end_ipv4", "isakmp.ts.start_ipv6",
    "isakmp.ts.end_ipv6", "isakmp.ike.nat_original_address_ipv4",
    "isakmp.ike.nat_original_address_ipv6",
    "ikev2.exchange_type",
    "ikev2.idi", "ikev2.idr", "ikev2.cfg.attr.internal_ip4_address",
    "ikev2.cfg.attr.internal_ip6_address", "ikev2.traffic_selector.initiator_ts_ipv4",
    "ikev2.traffic_selector.initiator_ts_ipv6", "ikev2.traffic_selector.responder_ts_ipv4",
    "ikev2.traffic_selector.responder_ts_ipv6", "_ws.col.info",
]

RADIUS_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "udp.stream", "udp.srcport", "udp.dstport",
    "radius.code", "radius.id", "radius.User_Name", "radius.Calling_Station_Id",
    "radius.Called_Station_Id", "radius.Acct_Status_Type", "radius.Framed_IP_Address",
    "radius.Acct_Session_Id", "radius.NAS_Identifier", "radius.Service_Type",
    "radius.Reply_Message", "radius.State", "radius.Class",
]

DNS_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "udp.stream", "tcp.stream", "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport",
    "dns.id", "dns.qry.name", "dns.qry.type", "dns.flags.response", "dns.flags.rcode",
    "dns.resp.name", "dns.a", "dns.aaaa", "dns.cname",
]

ICMP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "icmp.type", "icmp.code", "icmp.resp_in", "icmp.resp_to",
    "icmpv6.type", "icmpv6.code",
]

NAS_EPS_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "sctp.stream", "e212.imsi",
    "nas-eps.emm.message_type", "nas-eps.esm.message_type",
    "nas-eps.nas_msg_emm_type", "nas-eps.nas_msg_esm_type",
    "nas-eps.emm.cause", "nas-eps.esm.cause",
]

NAS_5GS_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "sctp.stream", "e212.imsi",
    "nas-5gs.mm.message_type", "nas-5gs.sm.message_type",
    "nas-5gs.mm.5gmm_cause", "nas-5gs.sm.cause",
]

TCP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.stream",
    "tcp.srcport", "tcp.dstport", "tcp.flags.reset", "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission", "tcp.analysis.duplicate_ack",
    "tcp.analysis.ack_lost_segment", "tcp.analysis.lost_segment",
]

UDP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "udp.stream",
    "udp.srcport", "udp.dstport", "udp.length",
]

PFCP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "udp.srcport", "udp.dstport", "pfcp.msg_type", "pfcp.cause", "pfcp.seqno",
    "pfcp.seid", "pfcp.node_id_ipv4", "pfcp.node_id_ipv6", "pfcp.node_id_fqdn",
    "_ws.col.info",
]

SCTP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "sctp.stream",
    "sctp.srcport", "sctp.dstport", "sctp.ppid", "sctp.chunk_type",
]

OPTIONAL_FILTER_FALLBACKS = {
    # Many tshark/Wireshark builds expose IKEv2 dissection under ISAKMP.
    "ikev2": ("isakmp",),
}


def _extract_optional_protocol(runner: TSharkRunner,
                               pcap_path: str,
                               key: str,
                               display_filter: str,
                               fields: list[str]) -> list[dict]:
    """Extract best-effort protocols without failing the entire upload."""
    filters_to_try = []
    for candidate in (display_filter, *OPTIONAL_FILTER_FALLBACKS.get(key, ())):
        if candidate and candidate not in filters_to_try:
            filters_to_try.append(candidate)

    for index, candidate in enumerate(filters_to_try):
        try:
            return runner.extract(pcap_path, candidate, fields)
        except TSharkParseError as exc:
            has_fallback = index < len(filters_to_try) - 1
            if has_fallback:
                _log_warning(
                    f"Optional {key} extraction failed for filter "
                    f"{candidate!r}: {exc}; retrying fallback"
                )
                continue
            _log_warning(
                f"Skipping optional {key} extraction because tshark "
                f"rejected filter {candidate!r}: {exc}"
            )
            return []

    return []


def _log_warning(message: str) -> None:
    log = getattr(logger, "warning", None) or getattr(logger, "info", None)
    if callable(log):
        log(message)


def _log_success(message: str) -> None:
    log = getattr(logger, "success", None) or getattr(logger, "info", None)
    if callable(log):
        log(message)


# ══════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════

def load_pcap(pcap_path: str,
              runner: TSharkRunner = None) -> dict:
    """
    Parse all protocols from a PCAP file.

    Args:
        pcap_path:  path to .pcap or .pcapng file
        runner:     TSharkRunner instance.
                    Pass a MockRunner in unit tests to avoid
                    needing a real tshark binary or PCAP file.
                    If None, a real TSharkRunner is constructed
                    from config.yaml settings.

    Returns:
        {
            "sip":      [list of parsed SIP records],
            "diameter": [list of parsed Diameter records],
            "inap":     [list of parsed INAP records],
            "gtp":      [list of raw flattened GTP dicts],
        }

    Raises:
        FileNotFoundError    if pcap_path does not exist
        TSharkNotFoundError  if tshark binary is missing
        TSharkTimeoutError   if tshark takes longer than timeout_sec
        TSharkParseError     if tshark output cannot be decoded
    """
    pcap_path = str(Path(pcap_path).resolve())

    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    # Build runner from config if not injected
    if runner is None:
        runner = TSharkRunner()

    if not runner.validate_pcap(pcap_path):
        raise ValueError(f"Unreadable or unsupported PCAP: {pcap_path}")

    logger.info(f"Loading PCAP: {Path(pcap_path).name}")
    logger.info(f"tshark version: {runner.version()}")

    # Read protocol filter overrides from config.yaml
    # (allows overriding "sip" with e.g. "sip and not sip.Method==OPTIONS")
    filters = cfg("tshark.filters", {})

    # ── SIP extraction ────────────────────────────────────────
    logger.info("Extracting SIP packets...")
    sip_flat   = runner.extract(
        pcap_path,
        filters.get("sip", "sip"),
        SIP_FIELDS)
    sip_parsed = parse_sip_packets(sip_flat)
    logger.info(f"  SIP: {len(sip_parsed)} packets parsed")

    # ── Diameter extraction ───────────────────────────────────
    logger.info("Extracting Diameter packets...")
    dia_flat   = runner.extract(
        pcap_path,
        filters.get("diameter", "diameter"),
        DIAMETER_FIELDS)
    dia_parsed = parse_diameter_packets(dia_flat)
    logger.info(f"  Diameter: {len(dia_parsed)} packets parsed")

    # ── INAP / TCAP extraction ────────────────────────────────
    logger.info("Extracting INAP/TCAP packets...")
    inap_flat   = runner.extract(
        pcap_path,
        filters.get("inap", "inap or tcap"),
        INAP_FIELDS)
    inap_parsed = parse_inap_packets(inap_flat)
    logger.info(f"  INAP: {len(inap_parsed)} packets parsed")

    # ── GTP extraction ────────────────────────────────────────
    logger.info("Extracting GTP packets...")
    gtp_flat = runner.extract(
        pcap_path,
        filters.get("gtp", "gtp or gtpv2"),
        GTP_FIELDS)
    gtp_parsed = parse_network_packets(gtp_flat, "GTP")
    logger.info(f"  GTP: {len(gtp_parsed)} packets parsed")

    protocol_specs = [
        ("s1ap", filters.get("s1ap", "s1ap or nas-eps"), S1AP_FIELDS, "S1AP"),
        ("ngap", filters.get("ngap", "ngap or nas-5gs"), NGAP_FIELDS, "NGAP"),
        ("ranap", filters.get("ranap", "ranap"), RANAP_FIELDS, "RANAP"),
        ("bssap", filters.get("bssap", "bssap"), BSSAP_FIELDS, "BSSAP"),
        ("map", filters.get("map", "gsm_map or tcap"), MAP_FIELDS, "MAP"),
        ("http", filters.get("http", "http or http2 or tls"), HTTP_FIELDS, "HTTP"),
        ("ikev2", filters.get("ikev2", "isakmp"), IKEV2_FIELDS, "IKEV2"),
        ("radius", filters.get("radius", "radius"), RADIUS_FIELDS, "RADIUS"),
        ("dns", filters.get("dns", "dns"), DNS_FIELDS, "DNS"),
        ("icmp", filters.get("icmp", "icmp or icmpv6"), ICMP_FIELDS, "ICMP"),
        ("nas_eps", filters.get("nas_eps", "nas-eps"), NAS_EPS_FIELDS, "NAS_EPS"),
        ("nas_5gs", filters.get("nas_5gs", "nas-5gs"), NAS_5GS_FIELDS, "NAS_5GS"),
        ("tcp", filters.get("tcp", "tcp"), TCP_FIELDS, "TCP"),
        ("udp", filters.get("udp", "udp"), UDP_FIELDS, "UDP"),
        ("pfcp", filters.get("pfcp", "pfcp"), PFCP_FIELDS, "PFCP"),
        ("sctp", filters.get("sctp", "sctp"), SCTP_FIELDS, "SCTP"),
    ]

    extra_results = {}
    for key, display_filter, fields, protocol_name in protocol_specs:
        logger.info(f"Extracting {protocol_name} packets...")
        raw_packets = _extract_optional_protocol(
            runner, pcap_path, key, display_filter, fields
        )
        extra_results[key] = parse_network_packets(raw_packets, protocol_name)
        logger.info(f"  {protocol_name}: {len(extra_results[key])} packets parsed")

    # ── Assemble result ───────────────────────────────────────
    results = {
        "sip":      sip_parsed,
        "diameter": dia_parsed,
        "inap":     inap_parsed,
        "gtp":      gtp_parsed,
        **extra_results,
    }

    total = sum(len(v) for v in results.values())
    _log_success(
        f"PCAP load complete — {total} total packets "
        f"(SIP:{len(sip_parsed)} "
        f"Diameter:{len(dia_parsed)} "
        f"INAP:{len(inap_parsed)} "
        f"GTP:{len(gtp_parsed)})"
    )

    return results


# ══════════════════════════════════════════════════════════════
#  PERSISTENCE HELPER
# ══════════════════════════════════════════════════════════════

def save_parsed(results: dict,
                output_dir: str = None) -> None:
    """
    Save parsed protocol packets to JSON files for inspection and reuse.

    Output directory defaults to config.yaml data.parsed.
    One file per protocol: sip_packets.json, diameter_packets.json, etc.

    These files are human-readable and useful for debugging correlation
    issues — you can open diameter_packets.json and check whether the
    MSISDN in each packet matches the calling party in sip_packets.json.
    """
    if output_dir is None:
        output_dir = cfg_path("data.parsed", "data/parsed")

    os.makedirs(output_dir, exist_ok=True)

    for protocol, packets in results.items():
        out_path = os.path.join(
            output_dir, f"{protocol}_packets.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(packets, f, indent=2, default=str)
        logger.info(
            f"Saved {len(packets):>4} {protocol:<10} packets "
            f"→ {out_path}")
