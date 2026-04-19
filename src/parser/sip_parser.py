# src/parser/sip_parser.py

import re
from typing import Optional

from loguru import logger


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_BRACKET_RE = re.compile(r"\[([0-9a-fA-F:]+)\]")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}\b")


def parse_sip_packet(raw: dict) -> Optional[dict]:
    call_id = _clean_text(_get(raw, "sip.Call-ID"))
    if not call_id:
        return None

    method = _clean_text(_get(raw, "sip.Method"))
    status_code = _clean_text(_get(raw, "sip.Status-Code"))

    from_uri = _get(raw, "sip.From")
    to_uri = _get(raw, "sip.To")
    reason_header = _clean_text(_get(raw, "sip.Reason"))
    status_line = _clean_text(_get(raw, "sip.Status-Line"))
    request_line = _clean_text(_get(raw, "sip.Request-Line"))

    timestamp = _to_float(_get(raw, "frame.time_epoch"))
    frame_num = _to_int(_get(raw, "frame.number"))

    src_ip = _first_present(raw, "ip.src", "ipv6.src")
    dst_ip = _first_present(raw, "ip.dst", "ipv6.dst")

    contact = _get(raw, "sip.Contact")
    via = _get(raw, "sip.Via")

    method = method.upper() if method else None

    return {
        "call_id": call_id,
        "frame_number": frame_num,
        "timestamp": timestamp,
        "method": method,
        "status_code": status_code,
        "from_uri": _clean_uri(from_uri),
        "to_uri": _clean_uri(to_uri),
        "reason": reason_header,
        "reason_header": reason_header,
        "status_line": status_line,
        "request_line": request_line,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "contact_ip": _extract_ip(contact),
        "via_ip": _extract_ip(via),
        "is_cancel": method == "CANCEL",
    }


def parse_sip_packets(raw_packets: list) -> list:
    records = []
    skipped = 0

    for raw in raw_packets:
        rec = parse_sip_packet(raw)
        if rec:
            records.append(rec)
        else:
            skipped += 1

    logger.info(f"SIP parser: {len(records)} valid, {skipped} skipped")
    return records


def _extract_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None

    text = str(value)
    match = _IPV4_RE.search(text)
    if match:
        return match.group(0)

    match = _IPV6_BRACKET_RE.search(text)
    if match:
        return match.group(1)

    match = _IPV6_RE.search(text)
    if match:
        return match.group(0)

    return None


def _clean_uri(uri: Optional[str]) -> Optional[str]:
    text = _clean_text(uri)
    if not text:
        return None

    if "<" in text and ">" in text:
        text = text.split("<", 1)[1].split(">", 1)[0]

    return (
        text.replace("sip:", "", 1)
        .replace("sips:", "", 1)
        .split(";", 1)[0]
        .strip()
    )


def _first_present(d: dict, *keys: str) -> Optional[str]:
    for key in keys:
        value = _clean_text(_get(d, key))
        if value:
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
    for k in keys:
        val = d.get(k)
        if val is None or val == "":
            continue
        if isinstance(val, list):
            values = [str(v).strip() for v in val if str(v).strip()]
            if not values:
                continue
            return values[0]
        return val
    return None
