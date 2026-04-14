"""
Session Correlation Engine — v11 (Production Grade)

Changes from v10:
  - Added _build_dia_index (was missing entirely)
  - Fixed O(n²) framed-IP loop → O(1) dict lookup
  - Added early-exit once best possible score (110) is reached
  - Fixed _ip_similarity false-positive: last-two-octets only, no single-octet match
  - Fixed _classify_node: narrow exception, not bare except
  - Fixed _dedup: skips None frame_number instead of collapsing all to one
  - Fixed time_cluster: respects min_overlap, consistent score threshold (best_score < 60)
  - Fixed _extract_user: tighter SIP URI regex (handles port numbers)
  - Fixed _group_sip_dialog: re-INVITE mid-call preserved as a new dialog segment
  - priority_ips dedup via seen-set, not dict.fromkeys on large intermediate list
  - All bare `except` replaced with specific exception types
  - Structured logging with correlation outcome stats
"""

import re
from collections import defaultdict
from loguru import logger
from typing import Optional

from src.config import cfg


# ============================================================
# MAIN ENTRY
# ============================================================

def build_sessions(parsed: dict) -> list:

    sip_pkts = parsed.get("sip", [])
    dia_pkts = parsed.get("diameter", [])
    inap_pkts = parsed.get("inap", [])
    gtp_pkts = parsed.get("gtp", [])
    generic_pkts = _collect_generic_packets(parsed)

    window_sec  = cfg("correlation.window_sec", 5)
    min_overlap = max(1, cfg("correlation.min_dia_overlap", 2))

    logger.info(f"Correlating: {len(sip_pkts)} SIP | {len(dia_pkts)} Diameter")

    # Group SIP by Call-ID
    sip_by_callid: dict[str, list] = defaultdict(list)
    for pkt in sip_pkts:
        cid = pkt.get("call_id")
        if cid:
            sip_by_callid[cid].append(pkt)

    # Build Diameter index ONCE — not per Call-ID
    dia_index = _build_dia_index(dia_pkts)

    sessions = []
    strategy_counts: dict[str, int] = defaultdict(int)

    for call_id, sip_msgs in sip_by_callid.items():

        sip_msgs = _sort_ts(sip_msgs)

        start_time = _first_ts(sip_msgs)
        end_time   = _last_ts(sip_msgs)

        calling, called = _extract_parties(sip_msgs)

        priority_ips = _extract_priority_ips(sip_msgs)

        dia_msgs, strategy = _correlate_diameter_fusion(
            dia_pkts,
            dia_index,
            calling,
            called,
            priority_ips,
            start_time,
            end_time,
            window_sec,
            min_overlap,
        )

        inap_msgs = _select_in_window(inap_pkts, start_time, end_time, window_sec)
        gtp_msgs = _select_in_window(gtp_pkts, start_time, end_time, window_sec)
        generic_msgs = _select_related_generic_packets(
            generic_pkts, start_time, end_time, window_sec, priority_ips
        )
        sip_flags = _build_sip_flags(sip_msgs)
        duration_ms = _duration_ms(start_time, end_time)
        final_sip_code = _final_sip_code(sip_msgs)

        strategy_counts[strategy] += 1

        sessions.append(
            _make_session_record(
                session_id=call_id,
                sip_msgs=sip_msgs,
                dia_msgs=dia_msgs,
                inap_msgs=inap_msgs,
                gtp_msgs=gtp_msgs,
                generic_msgs=generic_msgs,
                dia_correlation=strategy,
                calling=calling,
                called=called,
            )
        )

    non_sip_sessions = _build_non_sip_seed_sessions(
        dia_pkts=dia_pkts,
        inap_pkts=inap_pkts,
        gtp_pkts=gtp_pkts,
        generic_pkts=generic_pkts,
    )

    sessions.extend(non_sip_sessions)

    if sessions:
        sessions = _compact_correlated_sessions(sessions, window_sec)
    elif generic_pkts:
        sessions = _build_generic_sessions(generic_pkts)
    sessions = _suppress_low_value_sessions(sessions)

    logger.info(f"Sessions built: {len(sessions)} | strategies: {dict(strategy_counts)}")
    return sessions


# ============================================================
# DIAMETER INDEX  (was missing in v10)
# ============================================================

def _build_dia_index(dia_pkts: list) -> dict:
    """
    Build all lookup indexes from Diameter packets once.
    All keys are normalised (no leading +, stripped).
    """
    by_ip             = defaultdict(list)   # src/dst IP → pkts
    by_framed_ip      = defaultdict(list)   # Framed-IP AVP → pkts
    by_msisdn         = defaultdict(list)   # MSISDN → pkts
    by_msisdn_suffix  = defaultdict(list)   # last-8-digits → pkts
    by_imsi           = defaultdict(list)   # IMSI → pkts
    by_apn            = defaultdict(list)   # APN → pkts
    msisdn_to_imsi: dict[str, str] = {}

    for p in dia_pkts:
        src = p.get("src_ip")
        dst = p.get("dst_ip")
        if src:
            by_ip[src].append(p)
        if dst:
            by_ip[dst].append(p)

        framed = p.get("framed_ip")
        if framed:
            by_framed_ip[framed].append(p)

        msisdn = _norm(p.get("msisdn"))
        if msisdn:
            by_msisdn[msisdn].append(p)
            if len(msisdn) >= 8:
                by_msisdn_suffix[msisdn[-8:]].append(p)

        imsi = p.get("imsi")
        if imsi:
            by_imsi[imsi].append(p)
            if msisdn:
                msisdn_to_imsi.setdefault(msisdn, imsi)

        apn = p.get("apn")
        if apn:
            by_apn[apn].append(p)

    return {
        "by_ip":            dict(by_ip),
        "by_framed_ip":     dict(by_framed_ip),
        "by_msisdn":        dict(by_msisdn),
        "by_msisdn_suffix": dict(by_msisdn_suffix),
        "by_imsi":          dict(by_imsi),
        "by_apn":           dict(by_apn),
        "msisdn_to_imsi":   msisdn_to_imsi,
    }


# ============================================================
# MERGED LADDER FLOW (SIP + DIAMETER)
# ============================================================

def _build_merged_flow(sip_msgs: list, dia_msgs: list, inap_msgs: list, gtp_msgs: list, generic_msgs: list) -> list:

    flow = []

    for m in sip_msgs:
        msg = m.get("method") or m.get("status_code")
        if not msg:
            continue
        flow.append({
            "time":     m.get("timestamp"),
            "src":      _format_node(m.get("src_ip")),
            "dst":      _format_node(m.get("dst_ip")),
            "protocol": "SIP",
            "message":  msg,
            "call_id":  m.get("call_id"),
            "headers": {
                "from": m.get("from_uri"),
                "to":   m.get("to_uri"),
            },
        })

    for d in dia_msgs:
        cmd = d.get("command_name") or d.get("command_code") or "DIAMETER"
        result = d.get("result_code")
        result_text = d.get("result_text")
        display = cmd
        if result:
            display = f"{cmd} {result}"
        flow.append({
            "time":     d.get("timestamp"),
            "src":      _format_node(d.get("src_ip")),
            "dst":      _format_node(d.get("dst_ip")),
            "protocol": "DIAMETER",
            "message":  str(display),
            "short_label": str(display),
            "frame_number": d.get("frame_number"),
            "call_id":  d.get("session_id"),
            "failure":  d.get("is_failure"),
            "details": {
                "command_code": d.get("command_code"),
                "command_name": d.get("command_name"),
                "command_long_name": d.get("command_long_name"),
                "result_code": result,
                "result_text": result_text,
                "is_request": d.get("is_request"),
                "cc_request_type": d.get("cc_request_type_name") or d.get("cc_request_type"),
                "cc_request_number": d.get("cc_request_number"),
                "diameter_interface": d.get("diameter_interface"),
                "origin_host": d.get("origin_host"),
                "origin_realm": d.get("origin_realm"),
                "destination_host": d.get("destination_host"),
                "destination_realm": d.get("destination_realm"),
                "rating_group": d.get("rating_group"),
                "service_identifier": d.get("service_identifier"),
                "imsi": d.get("imsi"),
                "msisdn": d.get("msisdn"),
                "apn": d.get("apn"),
                "summary": d.get("summary"),
            },
        })

    for m in inap_msgs:
        flow.append({
            "time": m.get("timestamp"),
            "src": _format_node(m.get("src_ip")),
            "dst": _format_node(m.get("dst_ip")),
            "protocol": "INAP",
            "message": m.get("inap_op_name") or m.get("inap_opcode") or "INAP",
            "call_id": m.get("tcap_tid"),
        })

    for g in gtp_msgs:
        message = g.get("message") or g.get("gtpv2.message_type") or g.get("gtp.message_type") or "GTP"
        flow.append({
            "time": g.get("timestamp"),
            "src": _format_node(g.get("src_ip")),
            "dst": _format_node(g.get("dst_ip")),
            "protocol": "GTP",
            "message": message,
            "short_label": message,
            "frame_number": g.get("frame_number"),
            "failure": g.get("is_failure"),
            "call_id": g.get("gtp.tid"),
            "details": {
                "transaction_id": g.get("gtp.tid"),
                "imsi": g.get("gtpv2.imsi"),
                "cause_code": g.get("cause_code") or g.get("gtpv2.cause_value"),
                "summary": message,
            },
        })

    for packet in generic_msgs:
        flow.append({
            "time": packet.get("timestamp"),
            "src": _format_node(packet.get("src_ip")),
            "dst": _format_node(packet.get("dst_ip")),
            "protocol": packet.get("protocol"),
            "message": packet.get("message") or packet.get("protocol"),
            "short_label": packet.get("message") or packet.get("protocol"),
            "frame_number": packet.get("frame_number"),
            "failure": packet.get("is_failure"),
            "call_id": packet.get("transaction_id") or packet.get("stream_id"),
            "details": {
                "stream_id": packet.get("stream_id"),
                "transaction_id": packet.get("transaction_id"),
                "cause_code": packet.get("cause_code"),
                "transport": packet.get("transport"),
                "src_port": packet.get("src_port"),
                "dst_port": packet.get("dst_port"),
                "status_code": packet.get("status_code"),
                "dns_query": packet.get("dns_query"),
                "dns_answer": packet.get("dns_answer"),
                "dns_rcode": packet.get("dns_rcode"),
                "icmp_type": packet.get("icmp_type"),
                "icmp_code": packet.get("icmp_code"),
                "imsi": packet.get("imsi"),
                "msisdn": packet.get("msisdn"),
                "procedure": packet.get("procedure"),
            },
        })

    flow.sort(key=lambda x: x.get("time") or 0)
    flow = _group_sip_dialog(flow)
    return flow


def _make_session_record(
    session_id: str,
    sip_msgs: list,
    dia_msgs: list,
    inap_msgs: list,
    gtp_msgs: list,
    generic_msgs: list,
    dia_correlation: str,
    calling: Optional[str] = None,
    called: Optional[str] = None,
) -> dict:
    session = {
        "session_id": session_id,
        "call_id": session_id,
        "calling": calling,
        "called": called,
        "sip_msgs": _dedup(_sort_ts(sip_msgs)),
        "dia_msgs": _dedup(_sort_ts(dia_msgs)),
        "inap_msgs": _dedup(_sort_ts(inap_msgs)),
        "gtp_msgs": _dedup(_sort_ts(gtp_msgs)),
        "generic_msgs": _dedup(_sort_ts(generic_msgs)),
        "dia_correlation": dia_correlation,
    }
    return _refresh_session_record(session)


# ============================================================
# SIP DIALOG GROUPING  (fixed: re-INVITE handled correctly)
# ============================================================

_DIALOG_MESSAGES = frozenset({
    "100", "180", "183", "200", "ACK", "BYE", "487", "CANCEL",
    "PRACK", "UPDATE", "NOTIFY", "REFER",
})

def _group_sip_dialog(flow: list) -> list:
    """
    Group SIP events into dialogs. A new INVITE starts a new dialog segment.
    Non-SIP events are interleaved at their natural position.
    Re-INVITEs are preserved as distinct segments rather than flushed.
    """
    grouped = []
    dialog: list = []

    for f in flow:
        if f["protocol"] != "SIP":
            # Flush any open dialog before a non-SIP event so ordering is preserved
            if dialog:
                grouped.extend(dialog)
                dialog = []
            grouped.append(f)
            continue

        msg = f["message"]
        if msg == "INVITE":
            # Start a fresh dialog segment; keep prior dialog in output
            if dialog:
                grouped.extend(dialog)
            dialog = [f]
        else:
            dialog.append(f)

    if dialog:
        grouped.extend(dialog)

    return grouped


# ============================================================
# NODE CLASSIFICATION
# ============================================================

def _format_node(ip: Optional[str]) -> str:
    if not ip:
        return "UNKNOWN"
    return f"{_classify_node(ip)}\n{ip}"


def _classify_node(ip: str) -> str:
    try:
        if ip.startswith("10.") or ip.startswith("192.168."):
            return "CORE"
        if ip.startswith("172."):
            return "IMS"
        return "EXT"
    except AttributeError:
        return "UNKNOWN"


# ============================================================
# FUSION ENGINE  (O(1) lookup, early exit, fixed thresholds)
# ============================================================

_MAX_SCORE = 110  # framed_ip_fusion score — nothing can beat this

def _correlate_diameter_fusion(
    dia_pkts: list,
    dia_index: dict,
    calling: Optional[str],
    called: Optional[str],
    priority_ips: list,
    start_time: Optional[float],
    end_time: Optional[float],
    window_sec: int,
    min_overlap: int,
) -> tuple[list, str]:

    if not dia_pkts or not start_time:
        return [], "none"

    t_start = start_time - window_sec
    t_end   = (end_time or start_time) + window_sec

    def in_window(pkts: list) -> list:
        return [p for p in pkts if t_start <= (p.get("timestamp") or 0) <= t_end]

    best_match: list = []
    best_score: int  = 0
    best_strategy    = "unmatched"

    def _update(pkts, score, strategy):
        nonlocal best_match, best_score, best_strategy
        if score > best_score:
            best_match    = pkts
            best_score    = score
            best_strategy = strategy

    # ── Strategy 1: Framed-IP fusion (score 110) ─────────────────────────────
    for sip_ip in priority_ips:
        # Direct hit
        pkts = in_window(dia_index["by_framed_ip"].get(sip_ip, []))
        if pkts:
            _update(pkts, 110, "framed_ip_fusion")
            break  # 110 is maximum; no need to continue

        if best_score == _MAX_SCORE:
            break

        # NAT similarity hit (last two octets)
        for framed_ip, fpkts in dia_index["by_framed_ip"].items():
            if _ip_similarity(sip_ip, framed_ip):
                res = in_window(fpkts)
                if res:
                    _update(res, 108, "framed_ip_nat_similarity")

    if best_score == _MAX_SCORE:
        return _dedup(_sort_ts(best_match)), best_strategy

    # ── Strategy 2: IP-layer match (score 85) ────────────────────────────────
    for sip_ip in priority_ips:
        res = in_window(dia_index["by_ip"].get(sip_ip, []))
        if res:
            _update(res, 85, "ip_layer_match")
            break

    # ── Strategy 3: MSISDN exact (score 80) ──────────────────────────────────
    calling_norm = _norm(calling)
    if calling_norm:
        res = in_window(dia_index["by_msisdn"].get(calling_norm, []))
        if len(res) >= min_overlap:
            _update(res, 80, "msisdn_exact")

    # ── Strategy 4: MSISDN suffix / 8-digit rule (score 78) ─────────────────
    if calling_norm and len(calling_norm) >= 8:
        suffix = calling_norm[-8:]
        res = in_window(dia_index["by_msisdn_suffix"].get(suffix, []))
        if res:
            _update(res, 78, "msisdn_suffix_match")

    # ── Strategy 5: IMSI bridge (score 75) ───────────────────────────────────
    imsi = dia_index["msisdn_to_imsi"].get(calling_norm) if calling_norm else None
    if imsi:
        res = in_window(dia_index["by_imsi"].get(imsi, []))
        if len(res) >= min_overlap:
            _update(res, 75, "imsi_bridge")

    # ── Strategy 6: APN match (score 70) ─────────────────────────────────────
    called_norm = _norm(called)
    if called_norm:
        for apn, pkts in dia_index["by_apn"].items():
            if called_norm in apn:
                res = in_window(pkts)
                if len(res) >= min_overlap:
                    _update(res, 70, "apn_match")
                    break

    # ── Strategy 7: Time cluster fallback (only if nothing better found) ─────
    if best_score < 60:
        res = in_window(dia_pkts)
        if len(res) >= min_overlap:
            _update(res, 50, "time_cluster")

    if best_match:
        return _dedup(_sort_ts(best_match)), best_strategy

    return [], "unmatched"


# ============================================================
# HELPERS
# ============================================================

def _extract_priority_ips(sip_msgs: list) -> list:
    """
    Build a deduped, ordered list of candidate IPs from SIP messages.
    Contact and Via IPs are checked first (higher signal), then src/dst.
    """
    seen: set = set()
    result: list = []
    for m in sip_msgs:
        for key in ("contact_ip", "via_ip", "src_ip", "dst_ip"):
            ip = m.get(key)
            if ip and ip not in seen:
                seen.add(ip)
                result.append(ip)
    return result


def _build_non_sip_seed_sessions(
    dia_pkts: list,
    inap_pkts: list,
    gtp_pkts: list,
    generic_pkts: list,
) -> list:
    sessions = []

    for session_id, packets in _group_packets(
        dia_pkts,
        lambda packet: packet.get("session_id") or packet.get("imsi") or packet.get("msisdn") or _packet_peer_key(packet),
        "DIAMETER",
    ).items():
        sessions.append(
            _make_session_record(
                session_id=session_id,
                sip_msgs=[],
                dia_msgs=packets,
                inap_msgs=[],
                gtp_msgs=[],
                generic_msgs=[],
                dia_correlation="diameter_seed",
            )
        )

    for session_id, packets in _group_packets(
        inap_pkts,
        lambda packet: packet.get("tcap_tid") or packet.get("calling_number") or _packet_peer_key(packet),
        "INAP",
    ).items():
        sessions.append(
            _make_session_record(
                session_id=session_id,
                sip_msgs=[],
                dia_msgs=[],
                inap_msgs=packets,
                gtp_msgs=[],
                generic_msgs=[],
                dia_correlation="inap_seed",
            )
        )

    for session_id, packets in _group_packets(
        gtp_pkts,
        lambda packet: packet.get("gtp.tid") or packet.get("gtpv2.imsi") or _packet_peer_key(packet),
        "GTP",
    ).items():
        sessions.append(
            _make_session_record(
                session_id=session_id,
                sip_msgs=[],
                dia_msgs=[],
                inap_msgs=[],
                gtp_msgs=packets,
                generic_msgs=[],
                dia_correlation="gtp_seed",
            )
        )

    for session_id, packets in _group_packets(
        generic_pkts,
        lambda packet: (
            packet.get("transaction_id")
            or packet.get("pfcp.seid")
            or packet.get("pfcp.seqno")
            or packet.get("imsi")
            or packet.get("msisdn")
            or packet.get("stream_id")
            or _packet_peer_key(packet)
        ),
        None,
    ).items():
        for index, segment in enumerate(_segment_generic_packets(_sort_ts(packets))):
            segment_id = session_id if index == 0 else f"{session_id}:seg{index+1}"
            sessions.append(
                _make_session_record(
                    session_id=segment_id,
                    sip_msgs=[],
                    dia_msgs=[],
                    inap_msgs=[],
                    gtp_msgs=[],
                    generic_msgs=segment,
                    dia_correlation="generic_seed",
                )
            )

    return sessions


def _group_packets(packets: list, key_fn, prefix: Optional[str]) -> dict[str, list]:
    grouped: dict[str, list] = defaultdict(list)
    for packet in packets:
        key = key_fn(packet)
        if not key:
            continue
        session_key = f"{prefix}:{key}" if prefix else str(key)
        grouped[session_key].append(packet)
    return grouped


def _merge_correlated_sessions(sessions: list, window_sec: int) -> list:
    merged: list = []
    for session in sorted(sessions, key=lambda item: _session_time_bounds(item)[0] or 0):
        best_index = None
        best_score = 0
        for index, existing in enumerate(merged):
            score = _session_merge_score(existing, session, window_sec)
            if score > best_score:
                best_score = score
                best_index = index

        if best_index is not None and best_score >= 70:
            merged[best_index] = _merge_two_sessions(merged[best_index], session)
        else:
            merged.append(_refresh_session_record(session))

    merged = [_refresh_session_record(session) for session in merged]
    merged = _attach_transport_only_sessions(merged, window_sec)
    return [_refresh_session_record(session) for session in merged]


def _compact_correlated_sessions(sessions: list, window_sec: int, max_passes: int = 3) -> list:
    compacted = [_refresh_session_record(session) for session in sessions]
    previous_signature = None
    for _ in range(max(1, max_passes)):
        compacted = _merge_correlated_sessions(compacted, window_sec)
        signature = tuple(sorted(str(session.get("session_id")) for session in compacted))
        if signature == previous_signature:
            break
        previous_signature = signature
    return compacted


def _merge_two_sessions(base: dict, incoming: dict) -> dict:
    merged = {
        "session_id": min(str(base.get("session_id")), str(incoming.get("session_id"))),
        "call_id": base.get("call_id") if _has_sip(base) else incoming.get("call_id") or base.get("call_id"),
        "calling": base.get("calling") or incoming.get("calling"),
        "called": base.get("called") or incoming.get("called"),
        "sip_msgs": _merge_message_lists(base.get("sip_msgs", []), incoming.get("sip_msgs", [])),
        "dia_msgs": _merge_message_lists(base.get("dia_msgs", []), incoming.get("dia_msgs", [])),
        "inap_msgs": _merge_message_lists(base.get("inap_msgs", []), incoming.get("inap_msgs", [])),
        "gtp_msgs": _merge_message_lists(base.get("gtp_msgs", []), incoming.get("gtp_msgs", [])),
        "generic_msgs": _merge_message_lists(base.get("generic_msgs", []), incoming.get("generic_msgs", [])),
        "dia_correlation": _preferred_correlation(
            base.get("dia_correlation"),
            incoming.get("dia_correlation"),
        ),
    }
    return _refresh_session_record(merged)


def _merge_message_lists(first: list, second: list) -> list:
    return _dedup(_sort_ts(list(first) + list(second)))


def _attach_transport_only_sessions(sessions: list, window_sec: int) -> list:
    kept: list = []
    transport_only: list = []
    for session in sessions:
        if _is_transport_only_session(session):
            transport_only.append(session)
        else:
            kept.append(session)

    if not kept:
        return sessions

    for orphan in transport_only:
        best_index = None
        best_score = 0
        for index, candidate in enumerate(kept):
            score = _transport_attachment_score(candidate, orphan, window_sec)
            if score > best_score:
                best_score = score
                best_index = index
        if best_index is not None and best_score >= 55:
            kept[best_index] = _merge_two_sessions(kept[best_index], orphan)
        else:
            kept.append(orphan)
    return kept


def _is_transport_only_session(session: dict) -> bool:
    protocols = {str(proto).lower() for proto in session.get("protocols", [])}
    return bool(protocols) and protocols <= {"tcp", "udp", "sctp"}


def _transport_attachment_score(candidate: dict, orphan: dict, window_sec: int) -> int:
    candidate_desc = _session_descriptor(candidate)
    orphan_desc = _session_descriptor(orphan)
    time_gap = _time_gap_seconds(
        candidate_desc["start"],
        candidate_desc["end"],
        orphan_desc["start"],
        orphan_desc["end"],
    )
    if time_gap > max(3, window_sec * 3):
        return 0

    score = 0
    shared_pairs = candidate_desc["endpoint_pairs"] & orphan_desc["endpoint_pairs"]
    shared_ips = candidate_desc["ips"] & orphan_desc["ips"]
    shared_streams = candidate_desc["stream_ids"] & orphan_desc["stream_ids"]

    if shared_streams:
        score += 90
    if shared_pairs:
        score += 70
    elif len(shared_ips) >= 2:
        score += 60
    elif shared_ips:
        score += 40

    if candidate_desc["technologies"] & orphan_desc["technologies"]:
        score += 10

    return score


def _session_merge_score(left: dict, right: dict, window_sec: int) -> int:
    left_desc = _session_descriptor(left)
    right_desc = _session_descriptor(right)
    if _is_segmented_variant(left, right):
        if _has_procedure_restart_boundary(left, right):
            return 0
        time_gap = _time_gap_seconds(left_desc["start"], left_desc["end"], right_desc["start"], right_desc["end"])
        if time_gap > max(3, window_sec * 2):
            return 0

    shared_ids = left_desc["ids"] & right_desc["ids"]
    if shared_ids:
        return 120

    score = 0
    if left_desc["subscriber_ids"] & right_desc["subscriber_ids"]:
        score += 90

    if left_desc["stream_ids"] & right_desc["stream_ids"]:
        score += 85

    time_gap = _time_gap_seconds(left_desc["start"], left_desc["end"], right_desc["start"], right_desc["end"])
    within_window = time_gap <= max(2, window_sec * 2)
    shared_pairs = left_desc["endpoint_pairs"] & right_desc["endpoint_pairs"]
    shared_ips = left_desc["ips"] & right_desc["ips"]

    if within_window and shared_pairs:
        score += 80
    elif within_window and len(shared_ips) >= 2:
        score += 72
    elif within_window and shared_ips and (
        left_desc["non_transport_protocols"] or right_desc["non_transport_protocols"]
    ):
        score += 60

    if left_desc["technologies"] & right_desc["technologies"] and within_window:
        score += 15

    return score


def _is_segmented_variant(left: dict, right: dict) -> bool:
    left_id = str(left.get("session_id") or "")
    right_id = str(right.get("session_id") or "")
    left_base = left_id.split(":seg", 1)[0]
    right_base = right_id.split(":seg", 1)[0]
    return left_base == right_base and (":seg" in left_id or ":seg" in right_id)


def _has_procedure_restart_boundary(left: dict, right: dict) -> bool:
    left_marker = _last_semantic_message(left)
    right_marker = _first_semantic_message(right)
    if not left_marker or not right_marker:
        return False
    return _is_lte_completion_marker({"message": left_marker}) and _is_lte_start_marker({"message": right_marker})


def _session_descriptor(session: dict) -> dict:
    ids = set()
    subscriber_ids = set()
    ips = set()
    endpoint_pairs = set()
    stream_ids = set()
    technologies = set(session.get("technologies", []))
    protocols = set(session.get("protocols", []))

    call_id = session.get("call_id")
    if call_id:
        ids.add(f"call:{call_id}")

    for message in _all_session_messages(session):
        src_ip = message.get("src_ip")
        dst_ip = message.get("dst_ip")
        if src_ip:
            ips.add(src_ip)
        if dst_ip:
            ips.add(dst_ip)
        if src_ip or dst_ip:
            endpoint_pairs.add(tuple(sorted((src_ip or "?", dst_ip or "?"))))

    for sip in session.get("sip_msgs", []):
        for value in (sip.get("call_id"), sip.get("from_uri"), sip.get("to_uri")):
            if value:
                ids.add(f"sip:{value}")
        for value in (sip.get("contact_ip"), sip.get("via_ip")):
            if value:
                ips.add(value)

    for dia in session.get("dia_msgs", []):
        for value in (dia.get("session_id"), dia.get("framed_ip")):
            if value:
                ids.add(f"dia:{value}")
        for value in (dia.get("imsi"), dia.get("msisdn")):
            if value:
                subscriber_ids.add(_norm(value))
        if dia.get("framed_ip"):
            ips.add(dia["framed_ip"])

    for inap in session.get("inap_msgs", []):
        for value in (inap.get("tcap_tid"), inap.get("calling_number"), inap.get("called_number")):
            if value:
                ids.add(f"inap:{value}")
                subscriber_ids.add(_norm(value))

    for gtp in session.get("gtp_msgs", []):
        for field in ("gtp.tid", "gtpv2.imsi"):
            value = gtp.get(field)
            if value:
                ids.add(f"gtp:{value}")
                if "imsi" in field:
                    subscriber_ids.add(_norm(value))

    for packet in session.get("generic_msgs", []):
        for value in (packet.get("transaction_id"), packet.get("message")):
            if value and packet.get("transaction_id"):
                ids.add(f"{packet.get('protocol', 'GENERIC')}:{value}")
        for value in (packet.get("imsi"), packet.get("msisdn")):
            if value:
                subscriber_ids.add(_norm(value))
        if packet.get("stream_id"):
            stream_ids.add(f"{packet.get('protocol', 'GENERIC')}:{packet.get('stream_id')}")
        if packet.get("technology"):
            technologies.add(packet["technology"])
        if packet.get("protocol"):
            protocols.add(str(packet["protocol"]).lower())

    start, end = _session_time_bounds(session)
    return {
        "ids": ids,
        "subscriber_ids": {value for value in subscriber_ids if value},
        "ips": ips,
        "endpoint_pairs": endpoint_pairs,
        "stream_ids": stream_ids,
        "technologies": technologies,
        "non_transport_protocols": {
            proto
            for proto in protocols
            if proto not in {"tcp", "udp", "sctp"}
        },
        "start": start,
        "end": end,
    }


def _all_session_messages(session: dict) -> list:
    messages = []
    for key in ("sip_msgs", "dia_msgs", "inap_msgs", "gtp_msgs", "generic_msgs"):
        messages.extend(session.get(key, []))
    return messages


def _first_semantic_message(session: dict) -> Optional[str]:
    for item in session.get("flow", []):
        protocol = str(item.get("protocol") or "").upper()
        if protocol in {"SCTP", "TCP", "UDP", "ICMP"}:
            continue
        message = str(item.get("message") or "").strip()
        if message:
            return message
    return None


def _last_semantic_message(session: dict) -> Optional[str]:
    for item in reversed(session.get("flow", [])):
        protocol = str(item.get("protocol") or "").upper()
        if protocol in {"SCTP", "TCP", "UDP", "ICMP"}:
            continue
        message = str(item.get("message") or "").strip()
        if message:
            return message
    return None


def _session_time_bounds(session: dict) -> tuple[Optional[float], Optional[float]]:
    timestamps = [msg.get("timestamp") for msg in _all_session_messages(session) if msg.get("timestamp") is not None]
    if not timestamps:
        return None, None
    return min(timestamps), max(timestamps)


def _time_gap_seconds(
    left_start: Optional[float],
    left_end: Optional[float],
    right_start: Optional[float],
    right_end: Optional[float],
) -> float:
    if None in (left_start, left_end, right_start, right_end):
        return float("inf")
    if left_start <= right_end and right_start <= left_end:
        return 0.0
    return min(abs(right_start - left_end), abs(left_start - right_end))


def _preferred_correlation(*values: Optional[str]) -> str:
    ranked = [
        value for value in values
        if value and value not in {"none", "unmatched", "generic_seed"}
    ]
    if ranked:
        return ranked[0]
    return next((value for value in values if value), "none")


def _has_sip(session: dict) -> bool:
    return bool(session.get("sip_msgs"))


def _refresh_session_record(session: dict) -> dict:
    sip_msgs = _dedup(_sort_ts(session.get("sip_msgs", [])))
    dia_msgs = _dedup(_sort_ts(session.get("dia_msgs", [])))
    inap_msgs = _dedup(_sort_ts(session.get("inap_msgs", [])))
    gtp_msgs = _dedup(_sort_ts(session.get("gtp_msgs", [])))
    generic_msgs = _dedup(_sort_ts(session.get("generic_msgs", [])))
    protocol_buckets = _bucket_generic_messages(generic_msgs)

    start_time, end_time = _session_time_bounds(
        {
            "sip_msgs": sip_msgs,
            "dia_msgs": dia_msgs,
            "inap_msgs": inap_msgs,
            "gtp_msgs": gtp_msgs,
            "generic_msgs": generic_msgs,
        }
    )

    calling = session.get("calling")
    called = session.get("called")
    if sip_msgs:
        sip_calling, sip_called = _extract_parties(sip_msgs)
        calling = calling or sip_calling
        called = called or sip_called
    elif generic_msgs:
        calling = calling or generic_msgs[0].get("src_ip")
        called = called or generic_msgs[-1].get("dst_ip")

    final_sip_code = _final_sip_code(sip_msgs)
    flow = _build_merged_flow(sip_msgs, dia_msgs, inap_msgs, gtp_msgs, generic_msgs)
    flow_summary = _build_flow_string(sip_msgs) if sip_msgs else _generic_flow_summary(generic_msgs, dia_msgs, inap_msgs, gtp_msgs)
    sip_flags = _build_sip_flags(sip_msgs)
    protocols = _protocols_present(sip_msgs, dia_msgs, inap_msgs, gtp_msgs, generic_msgs)
    technologies = _technologies_present(sip_msgs, dia_msgs, inap_msgs, gtp_msgs, generic_msgs)
    session_id = _derive_session_id(session, sip_msgs, dia_msgs, inap_msgs, gtp_msgs, generic_msgs)

    refreshed = {
        "session_id": session_id,
        "call_id": session_id,
        "calling": calling,
        "called": called,
        "sip_msgs": sip_msgs,
        "dia_msgs": dia_msgs,
        "inap_msgs": inap_msgs,
        "gtp_msgs": gtp_msgs,
        "generic_msgs": generic_msgs,
        "http_msgs": protocol_buckets["HTTP"],
        "tcp_msgs": protocol_buckets["TCP"],
        "udp_msgs": protocol_buckets["UDP"],
        "sctp_msgs": protocol_buckets["SCTP"],
        "dns_msgs": protocol_buckets["DNS"],
        "icmp_msgs": protocol_buckets["ICMP"],
        "s1ap_msgs": protocol_buckets["S1AP"],
        "ngap_msgs": protocol_buckets["NGAP"],
        "ranap_msgs": protocol_buckets["RANAP"],
        "bssap_msgs": protocol_buckets["BSSAP"],
        "map_msgs": protocol_buckets["MAP"],
        "nas_eps_msgs": protocol_buckets["NAS_EPS"],
        "nas_5gs_msgs": protocol_buckets["NAS_5GS"],
        "pfcp_msgs": protocol_buckets["PFCP"],
        "flow": flow,
        "flow_summary": flow_summary,
        "imsi": _extract_imsi(dia_msgs) or _first_generic_identity(generic_msgs, "imsi"),
        "msisdn": _extract_msisdn(dia_msgs),
        "final_sip_code": final_sip_code,
        "dia_correlation": session.get("dia_correlation", "none"),
        "duration_ms": _duration_ms(start_time, end_time),
        "time_to_failure_ms": _time_to_failure_ms(sip_msgs, final_sip_code, start_time),
        "q850_cause": _extract_q850_cause(sip_msgs),
        "protocols": protocols,
        "technologies": technologies,
        **sip_flags,
    }
    return refreshed


def _bucket_generic_messages(generic_msgs: list) -> dict:
    buckets = {
        "HTTP": [],
        "TCP": [],
        "UDP": [],
        "SCTP": [],
        "DNS": [],
        "ICMP": [],
        "S1AP": [],
        "NGAP": [],
        "RANAP": [],
        "BSSAP": [],
        "MAP": [],
        "NAS_EPS": [],
        "NAS_5GS": [],
        "PFCP": [],
    }
    for message in generic_msgs:
        protocol = str(message.get("protocol") or "").upper()
        if protocol in buckets:
            buckets[protocol].append(message)
    return buckets


def _derive_session_id(session: dict, sip_msgs: list, dia_msgs: list, inap_msgs: list, gtp_msgs: list, generic_msgs: list) -> str:
    for candidate in (
        session.get("session_id"),
        session.get("call_id"),
        next((msg.get("call_id") for msg in sip_msgs if msg.get("call_id")), None),
        next((msg.get("session_id") for msg in dia_msgs if msg.get("session_id")), None),
        next((msg.get("tcap_tid") for msg in inap_msgs if msg.get("tcap_tid")), None),
        next((msg.get("gtp.tid") for msg in gtp_msgs if msg.get("gtp.tid")), None),
        next((msg.get("transaction_id") for msg in generic_msgs if msg.get("transaction_id")), None),
        next((msg.get("stream_id") for msg in generic_msgs if msg.get("stream_id")), None),
    ):
        if candidate:
            return str(candidate)
    return f"session:{len(sip_msgs) + len(dia_msgs) + len(inap_msgs) + len(gtp_msgs) + len(generic_msgs)}"


def _generic_flow_summary(generic_msgs: list, dia_msgs: list, inap_msgs: list, gtp_msgs: list) -> str:
    higher_layer_protocols = {
        str(message.get("protocol") or "").upper()
        for message in generic_msgs
        if message.get("protocol")
    } | ({ "GTP" } if gtp_msgs else set()) | ({ "DIAMETER" } if dia_msgs else set()) | ({ "INAP" } if inap_msgs else set())
    hide_transport_noise = bool(higher_layer_protocols - {"TCP", "UDP", "SCTP", "ICMP"})
    transport_noise_messages = {
        "UDP",
        "TCP",
        "DATA",
        "SACK",
        "HEARTBEAT",
        "HEARTBEAT_ACK",
        "COOKIE_ECHO",
        "COOKIE_ACK",
    }

    parts = []
    for message in dia_msgs:
        parts.append(message.get("command_code") or "DIAMETER")
    for message in inap_msgs:
        parts.append(message.get("inap_op_name") or "INAP")
    for message in gtp_msgs:
        parts.append(message.get("message") or message.get("gtpv2.message_type") or message.get("gtp.message_type") or "GTP")
    for message in generic_msgs:
        part = message.get("message") or message.get("protocol")
        if not part:
            continue
        part_text = str(part).strip()
        if not part_text:
            continue
        if hide_transport_noise and part_text in transport_noise_messages:
            continue
        if hide_transport_noise and part_text.isdigit():
            continue
        if hide_transport_noise and re.fullmatch(r"(?:SCTP|TCP|UDP)\s+procedure\s+\d+", part_text, flags=re.IGNORECASE):
            continue
        parts.append(part_text)
    unique_parts = []
    seen = set()
    for part in parts:
        if part and part not in seen:
            seen.add(part)
            unique_parts.append(str(part))
    return " → ".join(unique_parts[:10])


def _first_generic_identity(generic_msgs: list, field: str) -> Optional[str]:
    for message in generic_msgs:
        if message.get(field):
            return message[field]
    return None


def _collect_generic_packets(parsed: dict) -> list:
    packets = []
    for key in (
        "s1ap",
        "ngap",
        "ranap",
        "bssap",
        "map",
        "http",
        "dns",
        "icmp",
        "nas_eps",
        "nas_5gs",
        "tcp",
        "udp",
        "sctp",
        "pfcp",
    ):
        packets.extend(parsed.get(key, []))
    return _sort_ts(packets)


def _select_related_generic_packets(
    packets: list,
    start_time: Optional[float],
    end_time: Optional[float],
    window_sec: int,
    priority_ips: list,
) -> list:
    if not packets or start_time is None:
        return []

    t_start = start_time - window_sec
    t_end = (end_time or start_time) + window_sec
    priority = set(priority_ips)
    matched = []
    for packet in packets:
        ts = packet.get("timestamp") or 0
        if not (t_start <= ts <= t_end):
            continue
        if priority and packet.get("src_ip") not in priority and packet.get("dst_ip") not in priority:
            continue
        matched.append(packet)
    return _sort_ts(matched)


def _build_generic_sessions(packets: list) -> list:
    grouped: dict[str, list] = defaultdict(list)

    for packet in packets:
        key = (
            packet.get("transaction_id")
            or packet.get("pfcp.seid")
            or packet.get("pfcp.seqno")
            or packet.get("stream_id")
            or _packet_peer_key(packet)
        )
        grouped[f"{packet.get('protocol', 'GENERIC')}:{key}"].append(packet)

    sessions = []
    for session_id, msgs in grouped.items():
        for index, segment in enumerate(_segment_generic_packets(_sort_ts(msgs))):
            start_time = _first_ts(segment)
            end_time = _last_ts(segment)
            flow = _build_generic_flow(segment)
            segment_id = session_id if index == 0 else f"{session_id}:seg{index+1}"
            sessions.append(
                _refresh_session_record(
                    {
                    "session_id": segment_id,
                    "call_id": segment_id,
                    "calling": segment[0].get("src_ip"),
                    "called": segment[-1].get("dst_ip"),
                    "sip_msgs": [],
                    "dia_msgs": [],
                    "inap_msgs": [],
                    "gtp_msgs": [],
                    "generic_msgs": segment,
                    "flow": flow,
                    "flow_summary": " → ".join(
                        [msg.get("message") or msg.get("protocol") for msg in segment[:8]]
                    ),
                    "imsi": None,
                    "msisdn": None,
                    "final_sip_code": None,
                    "dia_correlation": "non_ims",
                    "duration_ms": _duration_ms(start_time, end_time),
                    "time_to_failure_ms": 0.0,
                    "q850_cause": None,
                    "protocols": sorted({msg.get("protocol") for msg in segment if msg.get("protocol")}),
                    "technologies": sorted({msg.get("technology") for msg in segment if msg.get("technology")}),
                    "has_invite": False,
                    "has_cancel": False,
                    "has_bye": False,
                    "has_prack": False,
                    "has_180": False,
                    "has_183": False,
                    "has_200": False,
                    "invite_count": 0,
                    "sip_msg_count": 0,
                    }
                )
            )
    return sessions


def _suppress_low_value_sessions(sessions: list) -> list:
    return [session for session in sessions if not _is_low_value_transport_noise(session)]


def _is_low_value_transport_noise(session: dict) -> bool:
    protocols = {str(proto).lower() for proto in session.get("protocols", [])}
    if not protocols or not protocols <= {"tcp", "udp", "sctp", "icmp"}:
        return _is_low_value_core_noise(session)
    if session.get("imsi") or session.get("msisdn"):
        return False
    generic_msgs = session.get("generic_msgs", [])
    if not generic_msgs:
        return False
    messages = [str(msg.get("message") or "").upper() for msg in generic_msgs]
    src_ips = {msg.get("src_ip") for msg in generic_msgs if msg.get("src_ip")}
    dst_ips = {msg.get("dst_ip") for msg in generic_msgs if msg.get("dst_ip")}
    benign = {
        "TCP",
        "UDP",
        "INIT",
        "INIT_ACK",
        "COOKIE_ECHO",
        "COOKIE_ACK",
        "ABORT",
        "SACK",
        "HEARTBEAT",
        "HEARTBEAT_ACK",
    }
    if protocols == {"sctp"} and set(messages) <= {"INIT", "ABORT"}:
        return True
    if protocols == {"sctp"} and set(messages) <= {"HEARTBEAT", "HEARTBEAT_ACK"}:
        return True
    if protocols == {"sctp"} and set(messages) <= {"DATA"}:
        return True
    if protocols <= {"icmp", "udp"}:
        icmp_types = {str(msg.get("icmp_type") or "") for msg in generic_msgs if str(msg.get("protocol") or "").upper() == "ICMP"}
        if icmp_types <= {"134"} or icmp_types <= {"134", "135"}:
            return True
    if protocols == {"tcp"} and set(messages) == {"TCP"}:
        if all(msg.get("reset") for msg in generic_msgs):
            return True
        if src_ips | dst_ips <= {"127.0.0.1"}:
            return True
    if len(generic_msgs) <= 4 and all(message in benign for message in messages):
        return True
    return False


def _is_low_value_core_noise(session: dict) -> bool:
    protocols = {str(proto).lower() for proto in session.get("protocols", [])}
    gtp_msgs = session.get("gtp_msgs", [])
    if protocols == {"gtp"} and 0 < len(gtp_msgs) <= 6:
        if all(
            str(msg.get("message") or "").upper() == "GTP"
            and not (msg.get("cause_code") or msg.get("gtpv2.cause_value"))
            and not (msg.get("gtp.tid") or msg.get("transaction_id"))
            for msg in gtp_msgs
        ):
            return True
    return False


def _segment_generic_packets(msgs: list) -> list[list]:
    if not msgs:
        return []
    protocols = {str(msg.get("protocol") or "").upper() for msg in msgs}
    legacy_mobility = bool(protocols & {"RANAP", "MAP"}) and not protocols & {"NGAP", "NAS_5GS"}
    if len(msgs) < 12 and not legacy_mobility:
        return [msgs]
    if not protocols <= {"NAS_EPS", "S1AP", "SCTP", "RANAP", "MAP", "UDP"}:
        return [msgs]

    segments: list[list] = []
    current: list = [msgs[0]]
    completion_seen = _is_lte_completion_marker(msgs[0])

    for previous, message in zip(msgs, msgs[1:]):
        gap = (message.get("timestamp") or 0) - (previous.get("timestamp") or 0)
        starts_new = _is_lte_start_marker(message)
        procedure_restart_gap = 0.5 if legacy_mobility else 2.0
        if current and (
            gap > 10.0
            or (gap > procedure_restart_gap and starts_new and completion_seen)
        ):
            segments.append(current)
            current = [message]
            completion_seen = _is_lte_completion_marker(message)
            continue
        current.append(message)
        completion_seen = completion_seen or _is_lte_completion_marker(message)

    if current:
        segments.append(current)
    return segments


def _is_lte_start_marker(message: dict) -> bool:
    text = str(message.get("message") or "").upper()
    return any(
        marker in text
        for marker in (
            "ATTACH REQUEST",
            "TRACKING AREA UPDATE REQUEST",
            "SERVICE REQUEST",
            "INITIAL UE MESSAGE",
            "INITIALUE-MESSAGE",
            "HANDOVER RESOURCE ALLOCATION",
            "FORWARD RELOCATION REQUEST",
        )
    )


def _is_lte_completion_marker(message: dict) -> bool:
    text = str(message.get("message") or "").upper()
    return any(
        marker in text
        for marker in (
            "ATTACH COMPLETE",
            "TRACKING AREA UPDATE COMPLETE",
            "UE CONTEXT RELEASE",
            "IU-RELEASECOMPLETE",
            "DELETE SESSION RESPONSE",
            "FORWARD RELOCATION RESPONSE",
        )
    )


def _build_generic_flow(msgs: list) -> list:
    flow = []
    for msg in msgs:
        flow.append(
            {
                "time": msg.get("timestamp"),
                "src": _format_node(msg.get("src_ip")),
                "dst": _format_node(msg.get("dst_ip")),
                "protocol": msg.get("protocol"),
                "message": msg.get("message") or msg.get("protocol"),
                "call_id": msg.get("transaction_id") or msg.get("stream_id"),
            }
        )
    return flow


def _packet_peer_key(packet: dict) -> str:
    src = packet.get("src_ip") or "unknown"
    dst = packet.get("dst_ip") or "unknown"
    src_port = packet.get("src_port") or "-"
    dst_port = packet.get("dst_port") or "-"
    return f"{src}:{src_port}->{dst}:{dst_port}"


def _select_in_window(pkts: list, start_time: Optional[float], end_time: Optional[float], window_sec: int) -> list:
    if not pkts or start_time is None:
        return []

    t_start = start_time - window_sec
    t_end = (end_time or start_time) + window_sec
    return _sort_ts(
        [p for p in pkts if t_start <= (p.get("timestamp") or 0) <= t_end]
    )


def _ip_similarity(ip1: str, ip2: str) -> bool:
    """
    Returns True only if the last TWO octets match — avoids single-octet
    collisions which are extremely common in /24 NAT pools.
    """
    try:
        a = ip1.split(".")
        b = ip2.split(".")
        return len(a) == 4 and len(b) == 4 and a[2] == b[2] and a[3] == b[3]
    except (AttributeError, IndexError):
        return False


_SIP_USER_RE = re.compile(
    r"sips?:([^@;>\s:]+)(?:@|$)",  # captures user part, stops before @, ;, >, whitespace, or port :
)

def _extract_user(uri: Optional[str]) -> Optional[str]:
    """
    Extract the user/number part from a SIP/SIPS URI.
    Handles tel: URIs and URIs with port numbers.
    Returns None if the URI is absent or unparseable.
    """
    if not uri:
        return None
    m = _SIP_USER_RE.search(uri)
    if m:
        return m.group(1)
    # tel: URI fallback
    tel = re.search(r"tel:([+\d\-().]+)", uri)
    if tel:
        return tel.group(1)
    return uri


def _extract_parties(sip_msgs: list) -> tuple[Optional[str], Optional[str]]:
    for m in sip_msgs:
        if m.get("method") == "INVITE":
            return (
                _extract_user(m.get("from_uri")),
                _extract_user(m.get("to_uri")),
            )
    return None, None


def _norm(num: Optional[str]) -> Optional[str]:
    if not num:
        return None
    return str(num).replace("+", "").strip()


def _sort_ts(msgs: list) -> list:
    return sorted(msgs, key=lambda m: m.get("timestamp") or 0)


def _first_ts(msgs: list) -> Optional[float]:
    ts = [m["timestamp"] for m in msgs if m.get("timestamp")]
    return min(ts) if ts else None


def _last_ts(msgs: list) -> Optional[float]:
    ts = [m["timestamp"] for m in msgs if m.get("timestamp")]
    return max(ts) if ts else None


def _build_flow_string(sip_msgs: list) -> str:
    steps: list[str] = []
    seen: set = set()
    for m in sip_msgs:
        step = m.get("method") or m.get("status_code")
        if step and step not in seen:
            seen.add(step)
            steps.append(step)
    return " → ".join(steps)


def _build_sip_flags(sip_msgs: list) -> dict:
    methods = [m.get("method") for m in sip_msgs if m.get("method")]
    statuses = [str(m.get("status_code")) for m in sip_msgs if m.get("status_code")]

    return {
        "has_invite": "INVITE" in methods,
        "has_cancel": "CANCEL" in methods,
        "has_bye": "BYE" in methods,
        "has_prack": "PRACK" in methods,
        "has_180": "180" in statuses,
        "has_183": "183" in statuses,
        "has_200": "200" in statuses,
        "invite_count": sum(1 for method in methods if method == "INVITE"),
        "sip_msg_count": len(sip_msgs),
    }


def _final_sip_code(sip_msgs: list) -> Optional[str]:
    code = None
    for m in sip_msgs:
        sc = m.get("status_code")
        if sc and sc != "100":
            code = sc
    return code


def _duration_ms(start_time: Optional[float], end_time: Optional[float]) -> float:
    if start_time is None or end_time is None:
        return 0.0
    return max(0.0, (end_time - start_time) * 1000.0)


def _time_to_failure_ms(
    sip_msgs: list,
    final_sip_code: Optional[str],
    start_time: Optional[float],
) -> float:
    if start_time is None or not final_sip_code or final_sip_code.startswith("2"):
        return 0.0

    for msg in sip_msgs:
        if str(msg.get("status_code")) == final_sip_code and msg.get("timestamp") is not None:
            return max(0.0, (msg["timestamp"] - start_time) * 1000.0)

    return 0.0


def _extract_q850_cause(sip_msgs: list) -> Optional[int]:
    for msg in reversed(sip_msgs):
        for field in ("reason", "reason_header", "status_line"):
            value = msg.get(field)
            cause = _parse_q850_from_text(value)
            if cause is not None:
                return cause
    return None


def _parse_q850_from_text(value: Optional[str]) -> Optional[int]:
    if not value:
        return None

    match = re.search(r'cause\s*=\s*"?(\d{1,3})"?', str(value), flags=re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


def _protocols_present(sip_msgs: list, dia_msgs: list, inap_msgs: list, gtp_msgs: list, generic_msgs: list) -> list:
    protocols = []
    if sip_msgs:
        protocols.append("sip")
    if dia_msgs:
        protocols.append("diameter")
    if inap_msgs:
        protocols.append("inap")
    if gtp_msgs:
        protocols.append("gtp")
    for packet in generic_msgs:
        proto = packet.get("protocol")
        if proto:
            protocols.append(str(proto).lower())
    return sorted(set(protocols))


def _technologies_present(sip_msgs: list, dia_msgs: list, inap_msgs: list, gtp_msgs: list, generic_msgs: list) -> list:
    technologies = []
    if sip_msgs or dia_msgs or inap_msgs:
        technologies.append("IMS")
    if gtp_msgs:
        technologies.append("LTE/4G")
    for packet in generic_msgs:
        tech = packet.get("technology")
        if tech:
            technologies.append(tech)
    return sorted(set(technologies))


def _dedup(pkts: list) -> list:
    seen: set = set()
    out: list = []
    for p in pkts:
        k = p.get("frame_number")
        if k is not None:
            k = (
                k,
                p.get("protocol"),
                p.get("transaction_id"),
                p.get("stream_id"),
                p.get("message"),
            )
        else:
            k = (
                p.get("protocol"),
                p.get("timestamp"),
                p.get("src_ip"),
                p.get("dst_ip"),
                p.get("message"),
                p.get("session_id"),
                p.get("transaction_id"),
                p.get("stream_id"),
                p.get("call_id"),
            )
        if k not in seen:
            seen.add(k)
            out.append(p)
    return out


def _extract_imsi(dia_msgs: list) -> Optional[str]:
    for m in dia_msgs:
        if m.get("imsi"):
            return m["imsi"]
    return None


def _extract_msisdn(dia_msgs: list) -> Optional[str]:
    for m in dia_msgs:
        if m.get("msisdn"):
            return m["msisdn"]
    return None


def save_sessions(sessions: list, output_path: Optional[str] = None) -> str:
    import json
    import os

    from src.config import cfg_path

    if output_path is None:
        output_path = os.path.join(cfg_path("data.parsed", "data/parsed"), "sessions.json")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(sessions, handle, indent=2, default=str)

    logger.info(f"Saved {len(sessions)} sessions → {output_path}")
    return output_path
