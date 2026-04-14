# src/parser/diameter_parser.py

from typing import Optional

from loguru import logger


SUCCESS_RESULT_CODES = {"2001", "2002"}
AUTH_FAILURE_CODES = {"4001", "5003"}
SUBSCRIBER_UNREACHABLE_CODES = {"5001", "5004"}
ROAMING_FAILURE_CODES = {"5004"}

DIAMETER_COMMAND_MAP = {
    "257": {"name": "Capabilities-Exchange", "request": "CER", "answer": "CEA", "interface": "Base"},
    "258": {"name": "Re-Auth", "request": "RAR", "answer": "RAA", "interface": "Base"},
    "272": {"name": "Credit-Control", "request": "CCR", "answer": "CCA", "interface": "Ro"},
    "300": {"name": "User-Authorization", "request": "UAR", "answer": "UAA", "interface": "Cx"},
    "301": {"name": "Server-Assignment", "request": "SAR", "answer": "SAA", "interface": "Cx"},
    "302": {"name": "Location-Info", "request": "LIR", "answer": "LIA", "interface": "Cx"},
    "303": {"name": "Multimedia-Auth", "request": "MAR", "answer": "MAA", "interface": "Cx"},
    "316": {"name": "Update-Location", "request": "ULR", "answer": "ULA", "interface": "S6a/S6d"},
    "317": {"name": "Cancel-Location", "request": "CLR", "answer": "CLA", "interface": "S6a/S6d"},
    "318": {"name": "Authentication-Information", "request": "AIR", "answer": "AIA", "interface": "S6a/S6d"},
}

DIAMETER_RESULT_CODE_MAP = {
    "2001": "DIAMETER_SUCCESS",
    "2002": "DIAMETER_LIMITED_SUCCESS",
    "4001": "AUTHENTICATION_REJECTED",
    "5001": "USER_UNKNOWN",
    "5003": "AUTHORIZATION_REJECTED",
    "5004": "ROAMING_NOT_ALLOWED",
}

CC_REQUEST_TYPE_MAP = {
    "1": "INITIAL",
    "2": "UPDATE",
    "3": "TERMINATION",
    "4": "EVENT",
}


def parse_diameter_packet(raw: dict) -> Optional[dict]:
    session_id = _clean_text(_get(raw, "diameter.Session-Id"))
    cmd_code = _clean_text(_get(raw, "diameter.cmd.code"))
    if not session_id or not cmd_code:
        return None

    result_code = _clean_text(
        _get(raw, "diameter.Result-Code", "diameter.Experimental-Result-Code")
    )
    timestamp = _to_float(_get(raw, "frame.time_epoch"))
    frame_num = _to_int(_get(raw, "frame.number"))

    src_ip = _clean_text(_get(raw, "ip.src", "ipv6.src"))
    dst_ip = _clean_text(_get(raw, "ip.dst", "ipv6.dst"))

    framed_ip = _clean_text(_get(raw, "diameter.Framed-IP-Address"))
    apn = _clean_text(_get(raw, "diameter.Called-Station-Id"))
    origin_host = _clean_text(_get(raw, "diameter.Origin-Host"))
    origin_realm = _clean_text(_get(raw, "diameter.Origin-Realm"))
    destination_host = _clean_text(_get(raw, "diameter.Destination-Host"))
    destination_realm = _clean_text(_get(raw, "diameter.Destination-Realm"))
    request_flag = _as_bool(_get(raw, "diameter.flags.request"))
    cc_request_type = _clean_text(_get(raw, "diameter.CC-Request-Type"))
    cc_request_number = _to_int(_get(raw, "diameter.CC-Request-Number"))
    rating_group = _clean_text(_get(raw, "diameter.Rating-Group"))
    service_identifier = _clean_text(_get(raw, "diameter.Service-Identifier"))
    granted_service_unit = _clean_text(_get(raw, "diameter.Granted-Service-Unit"))
    used_service_unit = _clean_text(_get(raw, "diameter.Used-Service-Unit"))

    imsi, msisdn = _extract_subscription_ids(raw)
    command_meta = DIAMETER_COMMAND_MAP.get(cmd_code, {})
    result_text = DIAMETER_RESULT_CODE_MAP.get(result_code, result_code)
    cc_request_type_name = CC_REQUEST_TYPE_MAP.get(cc_request_type, cc_request_type)
    request_name = command_meta.get("request", f"{cmd_code}R")
    answer_name = command_meta.get("answer", f"{cmd_code}A")
    command_name = request_name if request_flag else answer_name
    command_long_name = command_meta.get("name", "Diameter")
    is_failure = bool(result_code and result_code not in SUCCESS_RESULT_CODES)
    is_auth_failure = result_code in AUTH_FAILURE_CODES
    is_sub_unreachable = result_code in SUBSCRIBER_UNREACHABLE_CODES
    is_roaming_failure = result_code in ROAMING_FAILURE_CODES
    is_charging_failure = cmd_code == "272" and is_failure
    is_policy_reject = cmd_code in ("272", "258") and is_failure

    summary = command_name
    if not request_flag and result_code:
        summary = f"{command_name} {result_code}"
    if request_flag and cmd_code == "272" and cc_request_type_name:
        summary = f"{command_name} {cc_request_type_name}"

    return {
        "session_id": session_id,
        "frame_number": frame_num,
        "timestamp": timestamp,
        "cmd_code": cmd_code,
        "command_code": cmd_code,
        "command_name": command_name,
        "command_long_name": command_long_name,
        "diameter_interface": command_meta.get("interface"),
        "result_code": result_code,
        "result_text": result_text,
        "is_request": request_flag,
        "cc_request_type": cc_request_type,
        "cc_request_type_name": cc_request_type_name,
        "cc_request_number": cc_request_number,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "origin_host": origin_host,
        "origin_realm": origin_realm,
        "destination_host": destination_host,
        "destination_realm": destination_realm,
        "framed_ip": framed_ip,
        "apn": apn.lower() if apn else None,
        "imsi": imsi,
        "msisdn": msisdn,
        "rating_group": rating_group,
        "service_identifier": service_identifier,
        "granted_service_unit": granted_service_unit,
        "used_service_unit": used_service_unit,
        "summary": summary,
        "is_failure": is_failure,
        "is_auth_failure": is_auth_failure,
        "is_auth_reject": is_auth_failure,
        "is_sub_unreachable": is_sub_unreachable,
        "is_roaming_failure": is_roaming_failure,
        "is_charging_failure": is_charging_failure,
        "is_policy_reject": is_policy_reject,
    }


def parse_diameter_packets(raw_packets: list) -> list:
    records = []
    skipped = 0

    for raw in raw_packets:
        rec = parse_diameter_packet(raw)
        if rec:
            records.append(rec)
        else:
            skipped += 1

    logger.info(f"Diameter parser: {len(records)} valid, {skipped} skipped")
    return records


def _extract_subscription_ids(raw: dict) -> tuple[Optional[str], Optional[str]]:
    sub_id_raw = raw.get("diameter.Subscription-Id-Data")

    values: list[str] = []
    if isinstance(sub_id_raw, list):
        values = [str(v).strip() for v in sub_id_raw if str(v).strip()]
    elif sub_id_raw not in (None, ""):
        values = [str(sub_id_raw).strip()]

    imsi = None
    msisdn = None
    for value in values:
        digits = value.replace("+", "").strip()
        if digits.isdigit() and len(digits) >= 14 and imsi is None:
            imsi = digits
        elif digits and msisdn is None:
            msisdn = digits

    if imsi is None and values:
        imsi = values[0]
    if msisdn is None and len(values) > 1:
        msisdn = values[1]

    return imsi, msisdn


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


def _as_bool(value: Optional[object]) -> Optional[bool]:
    text = _clean_text(value)
    if text is None:
        return None
    lowered = text.lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
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
            return values[0] if len(values) == 1 else values
        return val
    return None
