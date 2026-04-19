# src/parser/inap_parser.py
"""
INAP / TCAP Parser — extracts Intelligent Network messages.

INAP sits on top of TCAP and handles IN services:
  CDIV  : Call Diversion
  VPN   : Virtual Private Network
  VVAS  : Voice VAS / announcements
  Prepaid charging via SCF/SSF

Your Trace-05.pcap has no INAP — but other traces may.
This parser is ready for when they do.

Key operations for RCA:
  0  InitialDP        — call arrived at SSF, asking SCF
  3  RouteSelectFailure — routing failed (critical RCA signal)
  20 Connect          — SCF connecting call to a number
  22 ReleaseCall      — SCF dropping the call
  46 ConnectToResource — MRF invoked (announcement about to play)
  60 PlayAnnouncement — audio being played to caller
"""

from loguru import logger
from typing import Optional


INAP_OPERATIONS = {
    "0":  "InitialDP",
    "1":  "OriginationAttemptAuthorized",
    "2":  "CollectedInformation",
    "3":  "RouteSelectFailure",
    "4":  "OCalledPartyBusy",
    "5":  "ONoAnswer",
    "6":  "OAnswer",
    "7":  "ODisconnect",
    "20": "Connect",
    "22": "ReleaseCall",
    "23": "RequestReportBCSMEvent",
    "24": "EventReportBCSM",
    "29": "Continue",
    "31": "InitiateCallAttempt",
    "40": "ApplyChargingReport",
    "41": "ApplyCharging",
    "43": "CallInformationReport",
    "46": "ConnectToResource",
    "48": "DisconnectForwardConnection",
    "60": "PlayAnnouncement",
    "63": "PromptAndCollectUserInformation",
}

SERVICE_LOGIC_OPS  = {"0", "20", "22", "29", "46", "60", "63"}
FAILURE_OPS        = {"3", "4", "5"}


def parse_inap_packet(raw: dict) -> Optional[dict]:
    """
    Parse one flattened packet into a clean INAP record.
    Returns None if no TCAP transaction ID found.
    """
    tcap_tid    = _get(raw, "tcap.tid",  "tcap_tid")
    inap_opcode = _get(raw, "inap.opcode", "inap.localValue",
                            "inap_opcode")
    service_key = _get(raw, "inap.serviceKey",  "inap.service_key")
    calling_num = _get(raw, "inap.callingPartyNumber",
                            "inap.calling_party_number")
    called_num  = _get(raw, "inap.calledPartyNumber",
                            "inap.called_party_number")
    cause       = _get(raw, "inap.cause_indicator", "inap.cause")
    timestamp   = _get(raw, "frame.time_epoch")
    frame_num   = _get(raw, "frame.number")
    src_ip      = _get(raw, "ip.src")
    dst_ip      = _get(raw, "ip.dst")

    if not tcap_tid:
        return None

    opcode_str = str(inap_opcode).strip() if inap_opcode else None
    op_name    = (INAP_OPERATIONS.get(opcode_str,
                  f"UNKNOWN_{opcode_str}")
                  if opcode_str else "UNKNOWN")

    is_failure         = opcode_str in FAILURE_OPS
    is_service_logic   = opcode_str in SERVICE_LOGIC_OPS
    is_mrf_invoked     = opcode_str in ("46", "60", "63")
    is_routing_failure = opcode_str == "3"
    is_initial_dp      = opcode_str == "0"
    is_release_call    = opcode_str == "22"

    return {
        # Identity
        "tcap_tid":           tcap_tid,
        "frame_number":       int(frame_num) if frame_num else None,
        "timestamp":          float(timestamp) if timestamp else None,

        # Operation
        "inap_opcode":        opcode_str,
        "inap_op_name":       op_name,
        "service_key":        service_key,

        # Subscribers
        "calling_number":     calling_num,
        "called_number":      called_num,
        "src_ip":             src_ip,
        "dst_ip":             dst_ip,
        "cause_indicator":    cause,

        # RCA flags
        "is_failure":         is_failure,
        "is_service_logic":   is_service_logic,
        "is_mrf_invoked":     is_mrf_invoked,
        "is_routing_failure": is_routing_failure,
        "is_initial_dp":      is_initial_dp,
        "is_release_call":    is_release_call,
    }


def parse_inap_packets(raw_packets: list) -> list:
    """Parse a list of raw flattened packets into INAP records."""
    records, skipped = [], 0
    for raw in raw_packets:
        rec = parse_inap_packet(raw)
        if rec:
            records.append(rec)
        else:
            skipped += 1
    logger.info(
        f"INAP parser: {len(records)} valid, {skipped} skipped")
    return records


def _get(d: dict, *keys) -> Optional[str]:
    for k in keys:
        val = d.get(k)
        if val is not None and val != "":
            if isinstance(val, list):
                values = [str(v).strip() for v in val if str(v).strip()]
                if not values:
                    continue
                return values[0]
            return str(val).strip()
    return None
