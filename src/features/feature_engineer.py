# src/features/feature_engineer.py
"""
Feature Engineering — converts session objects into ML feature vectors.

This is the most important module in the entire system.
The quality of features determines everything about ML performance.

Feature categories we build:
  1. Core SIP     — error codes, methods
  2. Flow         — message sequence pattern
  3. Timing       — delays, duration
  4. Absence      — what's MISSING (powerful RCA signal)
  5. Diameter     — charging / reachability signals
  6. INAP         — service logic signals
  7. Retry        — retransmission behaviour
  8. Subscriber   — calling/called party info

WHY absence features matter:
  A missing 180 Ringing + missing 200 OK + 487 = timeout pattern
  A missing CANCEL + 487 = network timeout, not user hangup
  These "what didn't happen" signals are often MORE informative
  than what did happen.
"""

import pandas as pd
import numpy as np
from loguru import logger
from typing import Optional
import os
import json
import hashlib
import math
from collections import Counter

from src.ml.anomaly import score_session_anomaly

try:  # pragma: no cover - optional dependency
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
except Exception:  # pragma: no cover - optional dependency
    IsolationForest = None
    DBSCAN = None


# ── SIP flow pattern vocabulary ───────────────────────────────
# These are the most common flow patterns in IMS networks.
# Each pattern maps to a likely RCA category.
KNOWN_FLOWS = {
    "INVITE → 100 → 180 → 200 → ACK":          "NORMAL_CALL",
    "INVITE → 100 → 183 → 200 → ACK":           "NORMAL_CALL_EARLY_MEDIA",
    "INVITE → 100 → 180 → 200 → ACK → BYE":    "NORMAL_CALL",
    "INVITE → 100 → 487 → ACK":                 "TIMEOUT_OR_CANCEL",
    "INVITE → 100 → 180 → 487 → ACK":           "NO_ANSWER_TIMEOUT",
    "INVITE → 100 → 183 → 487 → ACK":           "SERVICE_LOGIC_TIMEOUT",
    "INVITE → 100 → 480":                        "SUBSCRIBER_UNREACHABLE",
    "INVITE → 100 → 486":                        "USER_BUSY",
    "INVITE → 100 → 488":                        "CODEC_MISMATCH",
    "INVITE → 100 → 181 → 200 → ACK":           "CALL_FORWARDED",
}

# Q.850 cause → human meaning (for features + display)
Q850_MEANINGS = {
    1:  "unallocated_number",
    16: "normal_clearing",
    17: "user_busy",
    18: "no_user_responding",
    19: "no_answer",
    20: "subscriber_absent",
    21: "call_rejected",
    22: "number_changed",
    27: "destination_out_of_order",
    28: "invalid_number_format",
    31: "normal_unspecified",
    34: "no_circuit_available",
    38: "network_out_of_order",
    41: "temporary_failure",
    42: "switching_equipment_congestion",
    47: "resource_unavailable",
    50: "facility_not_subscribed",
    55: "incoming_calls_barred",
    57: "bearer_capability_not_authorised",
    58: "bearer_capability_not_available",
    63: "service_not_available",
    65: "bearer_capability_not_implemented",
    79: "service_not_implemented",
    88: "incompatible_destination",
    95: "invalid_message",
    97: "message_type_not_implemented",
    99: "information_element_not_implemented",
    102: "recovery_on_timer_expiry",
    111: "protocol_error",
    127: "interworking_unspecified",
}


def extract_features(session: dict) -> dict:
    """
    Extract all ML features from one session object.

    Input:  session dict from session_builder.build_sessions()
    Output: flat feature dict (all numeric or boolean values)

    Every feature has a comment explaining WHY it matters for RCA.
    """
    sip_msgs  = session.get("sip_msgs",  [])
    dia_msgs  = session.get("dia_msgs",  [])
    inap_msgs = session.get("inap_msgs", [])
    radius_msgs = session.get("radius_msgs", [])

    # ── 1. Core SIP features ───────────────────────────────────
    final_code   = session.get("final_sip_code")
    flow = session.get("flow_summary") or session.get("flow", "")
    if isinstance(flow, list):
        flow = " → ".join(str(item.get("message") or item.get("protocol") or "") for item in flow)

    # Numeric SIP code (ML needs numbers, not strings)
    sip_code_num = _safe_int(final_code)

    # SIP code category buckets
    # 1xx=provisional, 2xx=success, 4xx=client error, 5xx=server error
    sip_1xx = 1 if final_code and final_code.startswith("1") else 0
    sip_2xx = 1 if final_code and final_code.startswith("2") else 0
    sip_4xx = 1 if final_code and final_code.startswith("4") else 0
    sip_5xx = 1 if final_code and final_code.startswith("5") else 0

    # Specific failure codes — each has distinct RCA meaning
    is_480  = 1 if final_code == "480" else 0  # unreachable
    is_487  = 1 if final_code == "487" else 0  # terminated
    is_488  = 1 if final_code == "488" else 0  # codec mismatch
    is_486  = 1 if final_code == "486" else 0  # busy
    is_408  = 1 if final_code == "408" else 0  # timeout
    is_503  = 1 if final_code == "503" else 0  # server error
    is_200  = 1 if final_code == "200" else 0  # success

    # ── 2. Flow / sequence features ───────────────────────────
    # These capture the PATTERN of the call, not just the outcome.
    # "INVITE→183→487" is very different from "INVITE→180→487"

    has_invite      = int(session.get("has_invite",  False))
    has_cancel      = int(session.get("has_cancel",  False))
    has_bye         = int(session.get("has_bye",     False))
    has_180         = int(session.get("has_180",     False))
    has_183         = int(session.get("has_183",     False))
    has_200         = int(session.get("has_200",     False))
    has_prack       = int(session.get("has_prack",   False))

    # Count of each message type (retransmissions = network issues)
    invite_count    = session.get("invite_count", 1)
    sip_msg_count   = session.get("sip_msg_count", 0)

    # Was there early media? (183 = MRF or announcement involved)
    early_media     = int(has_183 == 1)

    # Flow matches a known pattern?
    known_flow      = 1 if flow in KNOWN_FLOWS else 0

    # Flow length (number of steps) — longer = more complex = more
    # opportunities for failure
    flow_length     = len(flow.split("→")) if flow else 0

    # ── 3. Absence features ────────────────────────────────────
    # What's MISSING from the call is often the most important
    # RCA signal. These are calculated ONLY for failed calls.

    # No 180/183 before failure = never reached the callee
    missing_ringing     = int(not has_180 and not has_183
                               and not has_200)
    # No CANCEL before 487 = timeout, not user hangup
    missing_cancel      = int(not has_cancel
                               and final_code == "487")
    # No 200 OK = call never answered
    missing_200_ok      = int(not has_200)
    # No BYE = call didn't end cleanly
    missing_bye         = int(not has_bye and has_200)

    # ── 4. Timing features ─────────────────────────────────────
    duration_ms         = session.get("duration_ms") or 0
    time_to_failure_ms  = session.get("time_to_failure_ms") or 0

    # Classify timing patterns
    # <500ms = immediate rejection (unreachable/barred)
    # 500ms-5s = fast failure (busy/routing)
    # >15s = timeout (no answer)
    is_immediate_fail   = int(0 < time_to_failure_ms < 500
                               if time_to_failure_ms else 0)
    is_fast_fail        = int(500 <= time_to_failure_ms < 5000
                               if time_to_failure_ms else 0)
    is_timeout_pattern  = int(time_to_failure_ms > 15000
                               if time_to_failure_ms else 0)

    # ── 5. Q.850 cause features ────────────────────────────────
    # Q.850 is gold — the PSTN/IMS reason for call termination.
    # We extract both the raw code and semantic bucket.
    q850 = session.get("q850_cause")
    q850_code           = q850 if q850 else -1

    # Q.850 semantic buckets (critical for RCA classification)
    q850_user_busy      = int(q850 == 17)
    q850_no_answer      = int(q850 in (18, 19))
    q850_unreachable    = int(q850 in (20, 27))
    q850_rejected       = int(q850 in (21, 50, 55))
    q850_network_fail   = int(q850 in (34, 38, 41, 42))
    q850_normal         = int(q850 in (16, 31))

    # ── 6. Diameter features ───────────────────────────────────
    dia_count           = len(dia_msgs)
    dia_failure_count   = sum(1 for d in dia_msgs
                               if d.get("is_failure"))

    # Charging flow: did CCR-Initial succeed?
    ccr_initial = next(
        (d for d in dia_msgs
         if d.get("cc_request_type") == "1"), None)
    ccr_term    = next(
        (d for d in dia_msgs
         if d.get("cc_request_type") == "3"), None)

    has_ccr_initial     = int(ccr_initial is not None)
    has_ccr_term        = int(ccr_term is not None)
    ccr_initial_ok      = int(ccr_initial is not None
                               and not ccr_initial.get("is_failure"))
    charging_failed     = int(any(d.get("is_charging_failure")
                                   for d in dia_msgs))
    sub_unreachable_dia = int(any(d.get("is_sub_unreachable")
                                   for d in dia_msgs))
    auth_failed_dia     = int(any(d.get("is_auth_failure")
                                   for d in dia_msgs))

    # ── 7. INAP features ───────────────────────────────────────
    inap_count          = len(inap_msgs)
    mrf_invoked         = int(any(m.get("is_mrf_invoked")
                                   for m in inap_msgs))
    inap_routing_fail   = int(any(m.get("is_routing_failure")
                                   for m in inap_msgs))
    inap_service_logic  = int(any(m.get("is_service_logic")
                                   for m in inap_msgs))
    inap_release_call   = int(any(m.get("is_release_call")
                                   for m in inap_msgs))
    service_key         = next(
        (m.get("service_key") for m in inap_msgs
         if m.get("service_key")), None)
    has_service_key     = int(service_key is not None)

    # ── 8. Multi-protocol features ─────────────────────────────
    # These cross-protocol signals are uniquely powerful —
    # they capture interactions between SIP and charging/IN layers

    # Diameter present = online charging involved
    has_diameter        = int(dia_count > 0)
    has_inap            = int(inap_count > 0)
    radius_count        = len(radius_msgs)
    radius_failure_count = sum(1 for m in radius_msgs if m.get("is_failure"))
    radius_accept_count = sum(1 for m in radius_msgs if str(m.get("radius_code") or "") in {"2", "5", "41", "44"})
    has_radius          = int(radius_count > 0)

    # Retransmissions = network instability signal
    has_retransmission  = int(invite_count > 1)

    intelligence = extract_trace_intelligence(session)

    # ── Assemble feature vector ────────────────────────────────
    features = {
        # Identity (not used for training, kept for traceability)
        "session_id":           session.get("session_id", ""),
        "calling":              session.get("calling", ""),
        "called":               session.get("called", ""),
        "flow":                 flow,

        # Core SIP
        "sip_code":             sip_code_num or 0,
        "sip_1xx":              sip_1xx,
        "sip_2xx":              sip_2xx,
        "sip_4xx":              sip_4xx,
        "sip_5xx":              sip_5xx,
        "is_480":               is_480,
        "is_487":               is_487,
        "is_488":               is_488,
        "is_486":               is_486,
        "is_408":               is_408,
        "is_503":               is_503,
        "is_200":               is_200,

        # Flow / sequence
        "has_invite":           has_invite,
        "has_cancel":           has_cancel,
        "has_bye":              has_bye,
        "has_180":              has_180,
        "has_183":              has_183,
        "has_200_ok":           has_200,
        "has_prack":            has_prack,
        "early_media":          early_media,
        "invite_count":         invite_count,
        "sip_msg_count":        sip_msg_count,
        "flow_length":          flow_length,
        "known_flow":           known_flow,

        # Absence (missing message signals)
        "missing_ringing":      missing_ringing,
        "missing_cancel":       missing_cancel,
        "missing_200_ok":       missing_200_ok,
        "missing_bye":          missing_bye,

        # Timing
        "duration_ms":          float(duration_ms),
        "time_to_failure_ms":   float(time_to_failure_ms),
        "is_immediate_fail":    is_immediate_fail,
        "is_fast_fail":         is_fast_fail,
        "is_timeout_pattern":   is_timeout_pattern,

        # Q.850
        "q850_code":            q850_code,
        "q850_user_busy":       q850_user_busy,
        "q850_no_answer":       q850_no_answer,
        "q850_unreachable":     q850_unreachable,
        "q850_rejected":        q850_rejected,
        "q850_network_fail":    q850_network_fail,
        "q850_normal":          q850_normal,

        # Diameter
        "dia_count":            dia_count,
        "dia_failure_count":    dia_failure_count,
        "has_ccr_initial":      has_ccr_initial,
        "has_ccr_term":         has_ccr_term,
        "ccr_initial_ok":       ccr_initial_ok,
        "charging_failed":      charging_failed,
        "sub_unreachable_dia":  sub_unreachable_dia,
        "auth_failed_dia":      auth_failed_dia,
        "has_diameter":         has_diameter,

        # RADIUS
        "radius_count":         radius_count,
        "radius_failure_count": radius_failure_count,
        "radius_accept_count":  radius_accept_count,
        "has_radius":           has_radius,

        # INAP
        "inap_count":           inap_count,
        "mrf_invoked":          mrf_invoked,
        "inap_routing_fail":    inap_routing_fail,
        "inap_service_logic":   inap_service_logic,
        "inap_release_call":    inap_release_call,
        "has_service_key":      has_service_key,
        "has_inap":             has_inap,

        # Multi-protocol
        "has_retransmission":   has_retransmission,

        # Trace intelligence (not part of legacy ML feature set yet)
        "protocol_count":       len(session.get("protocols", [])),
        "technology_count":     len(session.get("technologies", [])),
        "cross_protocol_hops":  intelligence["cross_protocol_hops"],
        "sequence_length":      intelligence["sequence_length"],
        "timer_anomaly_count":  intelligence["timer_anomaly_count"],
        "failure_signature":    intelligence["failure_signature"],
        "sequence_signature":   " | ".join(intelligence["sequence_signature"]),
    }

    return features


def extract_trace_intelligence(session: dict) -> dict:
    """Derive protocol-aware intelligence used by the learning loop."""
    flow = session.get("flow", []) or []
    sequence = []
    protocols = []
    timestamps = []
    timer_anomalies = []
    cross_protocol_links = Counter()

    for item in flow:
        protocol = str(item.get("protocol") or "GENERIC").upper()
        message = str(item.get("message") or protocol)
        token = f"{protocol}:{message}"
        sequence.append(token)
        protocols.append(protocol)
        if item.get("time") is not None:
            timestamps.append(_safe_float(item.get("time")))

    for idx in range(1, len(protocols)):
        if protocols[idx] != protocols[idx - 1]:
            cross_protocol_links[f"{protocols[idx - 1]}->{protocols[idx]}"] += 1

    for idx in range(1, len(timestamps)):
        gap_ms = max(0.0, (timestamps[idx] - timestamps[idx - 1]) * 1000)
        if gap_ms >= 2000:
            timer_anomalies.append(f"inter-message gap {int(gap_ms)} ms")

    if session.get("time_to_failure_ms", 0) and session["time_to_failure_ms"] > 15000:
        timer_anomalies.append("service timeout pattern")
    if session.get("invite_count", 0) > 1:
        timer_anomalies.append("signaling retransmission pattern")

    call_type = _infer_call_type(session)
    final_code = session.get("final_sip_code") or session.get("q850_cause") or "NA"
    failure_signature = f"{call_type}|{final_code}|{'/'.join(sorted(set(protocols))[:5])}"
    scenario = f"{call_type} - {session.get('rca', {}).get('rca_title', session.get('rca', {}).get('rca_label', 'Unknown'))}"

    return {
        "sequence_signature": sequence[:40],
        "sequence_length": len(sequence),
        "timer_anomalies": timer_anomalies,
        "timer_anomaly_count": len(timer_anomalies),
        "cross_protocol_causality": dict(cross_protocol_links),
        "cross_protocol_hops": sum(cross_protocol_links.values()),
        "failure_signature": failure_signature,
        "scenario": scenario,
        "call_type": call_type,
    }


def build_session_embedding(
    session: dict,
    features: dict | None = None,
    intelligence: dict | None = None,
    size: int = 48,
) -> list[float]:
    """Build a stable lightweight embedding from session behavior."""
    features = features or extract_features(session)
    intelligence = intelligence or extract_trace_intelligence(session)

    tokens = []
    tokens.extend(f"proto:{str(p).upper()}" for p in session.get("protocols", []))
    tokens.extend(f"tech:{t}" for t in session.get("technologies", []))
    tokens.extend(f"seq:{token}" for token in intelligence.get("sequence_signature", [])[:20])
    tokens.extend(f"timer:{token}" for token in intelligence.get("timer_anomalies", []))
    tokens.append(f"fail:{intelligence.get('failure_signature', 'unknown')}")
    tokens.append(f"rca:{session.get('rca', {}).get('rca_label', 'UNKNOWN')}")

    vector = [0.0] * size
    for token in tokens:
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        index = digest[0] % size
        sign = 1 if digest[1] % 2 == 0 else -1
        weight = 1 + (digest[2] / 255)
        vector[index] += sign * weight

    numeric = [
        float(features.get("duration_ms", 0)) / 10000,
        float(features.get("dia_failure_count", 0)),
        float(features.get("inap_count", 0)),
        float(features.get("protocol_count", 0)),
        float(features.get("technology_count", 0)),
        float(features.get("cross_protocol_hops", 0)),
        float(features.get("timer_anomaly_count", 0)),
    ]
    for idx, value in enumerate(numeric):
        vector[idx] += value

    norm = math.sqrt(sum(v * v for v in vector)) or 1.0
    return [round(float(v / norm), 6) for v in vector]


def detect_session_anomaly(
    session: dict,
    features: dict | None = None,
    intelligence: dict | None = None,
) -> dict:
    """Low-latency telecom anomaly ensemble."""
    features = features or extract_features(session)
    intelligence = intelligence or extract_trace_intelligence(session)
    return score_session_anomaly(session, features=features, intelligence=intelligence)


def cluster_sequence_signatures(signatures: list[list[float]]) -> list[int]:
    """Cluster embeddings for knowledge compaction workflows."""
    if not signatures:
        return []
    if DBSCAN is not None:  # pragma: no branch - optional dependency
        labels = DBSCAN(eps=0.25, min_samples=2, metric="cosine").fit_predict(np.array(signatures))
        return [int(label) for label in labels]
    seen = {}
    labels = []
    next_label = 0
    for signature in signatures:
        key = tuple(round(float(v), 2) for v in signature[:12])
        if key not in seen:
            seen[key] = next_label
            next_label += 1
        labels.append(seen[key])
    return labels


def build_feature_dataframe(sessions: list) -> pd.DataFrame:
    """
    Build a DataFrame of features from all sessions.
    One row per session. Saves to data/features/features.csv.
    """
    logger.info(
        f"Extracting features from {len(sessions)} sessions...")

    rows = []
    for session in sessions:
        try:
            feats = extract_features(session)
            rows.append(feats)
        except Exception as e:
            logger.warning(
                f"Feature extraction failed for session "
                f"{session.get('session_id','?')[:20]}: {e}")

    df = pd.DataFrame(rows)
    logger.success(
        f"Feature matrix: {df.shape[0]} rows × "
        f"{df.shape[1]} columns")
    return df


def save_features(df: pd.DataFrame,
                  output_dir: str = "data/features") -> str:
    """Save feature DataFrame to CSV."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "features.csv")
    df.to_csv(path, index=False)
    logger.info(f"Features saved → {path}")
    return path


def load_feature_matrix(path: str = "data/features/features.csv"
                         ) -> pd.DataFrame:
    """Load features CSV back into a DataFrame."""
    df = pd.read_csv(path)
    logger.info(
        f"Loaded feature matrix: "
        f"{df.shape[0]} rows × {df.shape[1]} cols")
    return df


# ── ML feature columns (excludes identity fields) ─────────────
# These are the columns passed to XGBoost for training/prediction
ML_FEATURE_COLS = [
    "sip_code", "sip_1xx", "sip_2xx", "sip_4xx", "sip_5xx",
    "is_480", "is_487", "is_488", "is_486", "is_408",
    "is_503", "is_200",
    "has_invite", "has_cancel", "has_bye",
    "has_180", "has_183", "has_200_ok", "has_prack",
    "early_media", "invite_count", "sip_msg_count",
    "flow_length", "known_flow",
    "missing_ringing", "missing_cancel",
    "missing_200_ok", "missing_bye",
    "duration_ms", "time_to_failure_ms",
    "is_immediate_fail", "is_fast_fail", "is_timeout_pattern",
    "q850_code", "q850_user_busy", "q850_no_answer",
    "q850_unreachable", "q850_rejected",
    "q850_network_fail", "q850_normal",
    "dia_count", "dia_failure_count",
    "has_ccr_initial", "has_ccr_term", "ccr_initial_ok",
    "charging_failed", "sub_unreachable_dia",
    "auth_failed_dia", "has_diameter",
    "radius_count", "radius_failure_count", "radius_accept_count", "has_radius",
    "inap_count", "mrf_invoked", "inap_routing_fail",
    "inap_service_logic", "inap_release_call",
    "has_service_key", "has_inap",
    "has_retransmission",
]


# ── Helper ─────────────────────────────────────────────────────
def _safe_int(val) -> Optional[int]:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _safe_float(val) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return 0.0


def _infer_call_type(session: dict) -> str:
    protocols = {str(p).upper() for p in session.get("protocols", [])}
    if "MAP" in protocols:
        return "MAP mobility or subscriber transaction"
    if "SIP" in protocols and "DIAMETER" in protocols:
        return "IMS voice session"
    if "NGAP" in protocols or "PFCP" in protocols:
        return "5G control-plane procedure"
    if "S1AP" in protocols or "GTP" in protocols:
        return "LTE control-plane procedure"
    if "INAP" in protocols:
        return "IN service logic transaction"
    return "Generic telecom session"
