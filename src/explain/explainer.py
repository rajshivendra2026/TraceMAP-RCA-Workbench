# src/explain/explainer.py
"""
RCA Explanation Engine

Uses SHAP to explain XGBoost predictions at the per-call level.
Produces:
  - Top contributing features with values and SHAP scores
  - Human-readable evidence sentences
  - Ladder diagram data (message sequence for rendering)
  - Full explainer dict consumed by GUI and CLI

Why SHAP?
  SHAP (SHapley Additive exPlanations) assigns each feature a value
  that represents its exact contribution to the prediction for THIS
  specific call. Unlike global feature importance, SHAP is local —
  it tells you WHY this particular call was classified this way.

  The sum of all SHAP values equals:
    prediction_score - baseline_score (average across training set)

  Positive SHAP = pushed toward predicted class
  Negative SHAP = pushed away from predicted class
"""

import numpy as np
import pandas as pd
from loguru import logger
from typing import Optional

from src.features.feature_engineer import ML_FEATURE_COLS

try:
    import shap
except Exception:  # pragma: no cover - optional dependency
    shap = None


# Q.850 cause code descriptions
Q850_TEXT = {
    1:  "unallocated number",
    16: "normal call clearing",
    17: "user busy",
    18: "no user responding",
    19: "no answer from user",
    20: "subscriber absent",
    21: "call rejected",
    22: "number changed",
    27: "destination out of order",
    28: "invalid number format",
    31: "normal unspecified",
    34: "no circuit available",
    38: "network out of order",
    41: "temporary failure",
    42: "switching equipment congestion",
    47: "resource unavailable",
    50: "facility not subscribed",
    55: "incoming calls barred",
    57: "bearer capability not authorised",
    88: "incompatible destination",
    102: "recovery on timer expiry",
}

# Diameter result code descriptions
DIA_RESULT_TEXT = {
    "2001": "SUCCESS",
    "2002": "LIMITED_SUCCESS",
    "3001": "COMMAND_UNSUPPORTED",
    "3002": "UNABLE_TO_DELIVER",
    "4001": "AUTHENTICATION_REJECTED",
    "4012": "CREDIT_LIMIT_REACHED",
    "5003": "AUTHORIZATION_REJECTED",
    "5012": "UNABLE_TO_COMPLY",
}


def explain_prediction(
        session: dict,
        features: dict,
        model,
        encoder,
        top_n: int = 10) -> dict:
    """
    Generate full explanation for one session prediction.

    Args:
        session:  session dict from session_builder
        features: feature dict from feature_engineer
        model:    trained XGBClassifier
        encoder:  fitted LabelEncoder
        top_n:    number of top SHAP features to return

    Returns:
        explanation dict consumed by GUI and CLI
    """
    # ── Build feature vector ───────────────────────────────────
    X = _features_to_vector(features)

    # ── Predict ───────────────────────────────────────────────
    pred_idx   = model.predict(X)[0]
    pred_proba = model.predict_proba(X)[0]
    pred_label = encoder.inverse_transform([pred_idx])[0]
    confidence = round(float(pred_proba[pred_idx]) * 100, 1)

    logger.info(
        f"Prediction: {pred_label} ({confidence}%)")

    # ── SHAP values ───────────────────────────────────────────
    try:
        if shap is None:
            raise RuntimeError("SHAP is not installed")

        explainer   = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X)

        # For multi-class: shap_values is list of arrays
        if isinstance(shap_values, list):
            sv = shap_values[pred_idx][0]
        else:
            sv = shap_values[0]

        # Map feature names → SHAP scores
        shap_dict = dict(zip(ML_FEATURE_COLS, sv))

        # Sort by absolute value
        top_shap = sorted(
            shap_dict.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:top_n]

    except Exception as e:
        logger.warning(f"SHAP computation failed: {e}")
        # Fallback: use feature importance as proxy
        fi = model.feature_importances_
        shap_dict = dict(zip(ML_FEATURE_COLS, fi))
        top_shap = sorted(
            shap_dict.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:top_n]

    # ── Build SHAP output list ────────────────────────────────
    shap_output = []
    for feat, score in top_shap:
        feat_val = features.get(feat, 0)
        shap_output.append({
            "feature":     feat,
            "value":       feat_val,
            "shap_score":  round(float(score), 4),
            "direction":   "positive" if score > 0 else "negative",
            "description": _feature_description(feat, feat_val),
        })

    # ── Human-readable evidence ───────────────────────────────
    evidence = _build_evidence(session, features, pred_label)

    # ── Ladder diagram data ───────────────────────────────────
    ladder = _build_ladder_data(session)

    # ── Per-class probabilities ───────────────────────────────
    class_probs = [
        {
            "label":       encoder.inverse_transform([i])[0],
            "probability": round(float(p) * 100, 1),
        }
        for i, p in enumerate(pred_proba)
    ]
    class_probs.sort(key=lambda x: -x["probability"])

    return {
        # Core prediction
        "rca_label":    pred_label,
        "confidence":   confidence,
        "confidence_pct": int(confidence),

        # Evidence
        "evidence":     evidence,
        "rule_matched": session.get("rca", {}).get(
                            "rule_matched", "ML"),

        # SHAP
        "shap_features": shap_output,
        "shap_all":      {k: round(float(v), 4)
                          for k, v in shap_dict.items()},

        # Class probabilities
        "class_probs":  class_probs[:5],

        # Ladder
        "ladder":       ladder,

        # Session metadata
        "call_id":      session.get("call_id", ""),
        "calling":      session.get("calling", ""),
        "called":       session.get("called", ""),
        "flow":         session.get("flow_summary") or session.get("flow", ""),
        "duration_ms":  session.get("duration_ms", 0),
        "protocols":    session.get("protocols", []),
    }


def explain_rule_based(session: dict, features: dict) -> dict:
    """
    Generate explanation using rule engine output (no ML model needed).
    Used when ML model hasn't been trained yet.
    """
    rca    = session.get("rca", {})
    ladder = _build_ladder_data(session)

    # Simulate SHAP-style scores from rule signals
    shap_output = _simulate_shap(features, rca.get("rca_label", "UNKNOWN"))

    return {
        "rca_label":      rca.get("rca_label", "UNKNOWN"),
        "confidence":     rca.get("confidence_pct", 50),
        "confidence_pct": rca.get("confidence_pct", 50),
        "evidence":       rca.get("evidence", []),
        "rule_matched":   rca.get("rule_matched", "RULES"),
        "shap_features":  shap_output,
        "shap_all":       {},
        "class_probs":    [],
        "ladder":         ladder,
        "call_id":        session.get("call_id", ""),
        "calling":        session.get("calling", ""),
        "called":         session.get("called", ""),
        "flow":           session.get("flow_summary") or session.get("flow", ""),
        "duration_ms":    session.get("duration_ms", 0),
        "protocols":      session.get("protocols", []),
    }


# ── Ladder diagram builder ─────────────────────────────────────

def _build_ladder_data(session: dict) -> dict:
    """
    Build structured ladder diagram data for the GUI.

    Returns a dict with:
      - entities: list of entity names (columns)
      - messages: list of message dicts with positions + styling
    """
    sip_msgs  = session.get("sip_msgs",  [])
    dia_msgs  = session.get("dia_msgs",  [])
    inap_msgs = session.get("inap_msgs", [])

    # Determine entities
    entities = ["UE / Caller", "P-CSCF", "S-CSCF / TAS"]
    has_dia  = len(dia_msgs) > 0
    has_inap = len(inap_msgs) > 0
    if has_dia:   entities.append("OCS (Ro/Diameter)")
    if has_inap:  entities.append("SCF (INAP)")

    # Merge all messages sorted by timestamp
    all_msgs = []
    for m in sip_msgs:
        all_msgs.append({**m, "_proto": "sip"})
    for m in dia_msgs:
        all_msgs.append({**m, "_proto": "diameter"})
    for m in inap_msgs:
        all_msgs.append({**m, "_proto": "inap"})

    all_msgs.sort(key=lambda x: x.get("timestamp") or 0)

    # Build message list for rendering
    messages = []
    for idx, msg in enumerate(all_msgs):
        proto = msg["_proto"]

        if proto == "sip":
            label    = msg.get("method") or msg.get("status_code") or "?"
            is_req   = msg.get("is_request", msg.get("method") is not None)
            is_fail  = msg.get("is_failure", False)
            is_ok    = msg.get("status_code") in ("200", "183")
            is_cancel= msg.get("is_cancel", False)

            color = ("#f87171" if is_fail
                     else "#4ade80" if is_ok
                     else "#facc15" if is_cancel
                     else "#38bdf8")

            messages.append({
                "idx":        idx,
                "proto":      "sip",
                "label":      label,
                "timestamp":  msg.get("timestamp"),
                "from_entity":0 if is_req else 2,
                "to_entity":  2 if is_req else 0,
                "color":      color,
                "dashed":     False,
                "is_failure": is_fail,
                "is_ok":      is_ok,
                "q850":       msg.get("q850_cause"),
                "reason":     msg.get("reason_header"),
                "src_ip":     msg.get("src_ip"),
                "dst_ip":     msg.get("dst_ip"),
                "cseq":       msg.get("cseq"),
                "from_uri":   msg.get("from_uri"),
                "to_uri":     msg.get("to_uri"),
            })

        elif proto == "diameter":
            is_req   = msg.get("is_request", True)
            is_fail  = msg.get("is_failure", False)
            rc       = msg.get("result_code")
            cc_type  = msg.get("cc_request_name", "")
            label    = _dia_label(msg)
            color    = ("#f87171" if is_fail
                        else "#4ade80" if rc == "2001"
                        else "#fb923c")

            # S-CSCF ↔ OCS
            dia_col = len(entities) - (2 if has_inap else 1)
            messages.append({
                "idx":           idx,
                "proto":         "diameter",
                "label":         label,
                "timestamp":     msg.get("timestamp"),
                "from_entity":   2 if is_req else dia_col,
                "to_entity":     dia_col if is_req else 2,
                "color":         color,
                "dashed":        True,
                "is_failure":    is_fail,
                "is_ok":         rc == "2001",
                "result_code":   rc,
                "result_name":   DIA_RESULT_TEXT.get(str(rc), ""),
                "cmd_code":      msg.get("cmd_code"),
                "cmd_name":      msg.get("cmd_name"),
                "cc_type":       cc_type,
                "session_id":    msg.get("session_id"),
                "origin_host":   msg.get("origin_host"),
                "dest_host":     msg.get("dest_host"),
                "imsi":          msg.get("imsi"),
                "msisdn":        msg.get("msisdn"),
            })

        elif proto == "inap":
            op_name = msg.get("inap_op_name", "INAP")
            is_fail = msg.get("is_failure", False)
            color   = "#f87171" if is_fail else "#a78bfa"
            inap_col = len(entities) - 1
            messages.append({
                "idx":        idx,
                "proto":      "inap",
                "label":      op_name[:16],
                "timestamp":  msg.get("timestamp"),
                "from_entity":2,
                "to_entity":  inap_col,
                "color":      color,
                "dashed":     True,
                "is_failure": is_fail,
                "service_key":msg.get("service_key"),
                "tcap_tid":   msg.get("tcap_tid"),
            })

    return {
        "entities": entities,
        "messages": messages,
    }


def _dia_label(msg: dict) -> str:
    """Build short Diameter label for ladder."""
    is_req  = msg.get("is_request", True)
    cc_name = msg.get("cc_request_name", "")
    rc      = msg.get("result_code", "")

    short = {
        "INITIAL_REQUEST":     "CCR-I" if is_req else "CCA-I",
        "UPDATE_REQUEST":      "CCR-U" if is_req else "CCA-U",
        "TERMINATION_REQUEST": "CCR-T" if is_req else "CCA-T",
        "EVENT_REQUEST":       "CCR-E" if is_req else "CCA-E",
    }
    base = short.get(cc_name, "CCR" if is_req else "CCA")
    return f"{base} [{rc}]" if rc else base


# ── Evidence builder ───────────────────────────────────────────

def _build_evidence(session: dict,
                    features: dict,
                    label: str) -> list:
    """
    Build human-readable evidence list for a given RCA label.
    Combines rule-engine evidence with feature-derived signals.
    """
    rule_ev = session.get("rca", {}).get("evidence", [])
    if rule_ev:
        return rule_ev

    ev = []
    code = session.get("final_sip_code")
    if code:
        ev.append(f"Final SIP response: {code}")

    flow = session.get("flow_summary") or session.get("flow", "")
    if flow:
        ev.append(f"Call flow: {flow}")

    dur = session.get("duration_ms", 0)
    if dur:
        ev.append(f"Duration: {int(dur)}ms")

    q850 = session.get("q850_cause")
    if q850:
        ev.append(
            f"Q.850 cause {q850}: {Q850_TEXT.get(q850, 'cause '+str(q850))}")

    if features.get("charging_failed"):
        rc = None
        for d in session.get("dia_msgs", []):
            if d.get("is_charging_failure"):
                rc = d.get("result_code")
                break
        ev.append(
            f"Diameter charging failure"
            + (f" (result {rc}: {DIA_RESULT_TEXT.get(str(rc),'')})" if rc else ""))

    if features.get("missing_cancel") and code == "487":
        ev.append("No CANCEL present — user did not hang up")

    if features.get("is_timeout_pattern"):
        ttf = features.get("time_to_failure_ms", 0)
        ev.append(f"Time to failure: {int(ttf)}ms — timer expiry pattern")

    return ev or [f"RCA: {label}"]


# ── SHAP simulation (rule-based fallback) ──────────────────────

def _simulate_shap(features: dict, label: str) -> list:
    """
    Simulate SHAP scores from rule signals when ML model is absent.
    Scores are domain-knowledge weights, not real SHAP values.
    """
    weights = {
        "USER_ABORT":
            [("has_cancel",0.88),("is_487",0.72),("missing_cancel",-0.65),("has_180",0.31)],
        "NO_ANSWER_TIMEOUT":
            [("missing_cancel",0.90),("has_180",0.78),("is_487",0.70),
             ("time_to_failure_ms",0.65),("is_timeout_pattern",0.60),("has_200_ok",-0.44)],
        "SERVICE_TIMEOUT":
            [("has_183",0.86),("early_media",0.80),("is_487",0.68),
             ("missing_cancel",0.62),("inap_count",0.44),("has_200_ok",-0.40)],
        "SUBSCRIBER_UNREACHABLE":
            [("is_480",0.95),("q850_unreachable",0.82),("missing_ringing",0.75),
             ("is_immediate_fail",0.68),("has_200_ok",-0.55),("dia_failure_count",0.32)],
        "USER_BUSY":
            [("is_486",0.94),("q850_user_busy",0.82),("is_fast_fail",0.60),
             ("has_200_ok",-0.50),("missing_200_ok",0.42)],
        "CODEC_MISMATCH":
            [("is_488",0.95),("is_immediate_fail",0.74),
             ("has_200_ok",-0.55),("missing_200_ok",0.44)],
        "CHARGING_FAILURE":
            [("charging_failed",0.93),("dia_failure_count",0.85),
             ("ccr_initial_ok",-0.78),("has_ccr_term",-0.62),("has_200_ok",-0.50)],
        "NORMAL_CALL":
            [("is_200",0.92),("has_bye",0.86),("has_200_ok",0.83),
             ("has_180",0.56),("ccr_initial_ok",0.48),("is_487",-0.40)],
        "ROUTING_FAILURE":
            [("inap_routing_fail",0.92),("has_inap",0.80),("inap_release_call",0.70),
             ("has_200_ok",-0.55),("is_487",0.48)],
        "ANNOUNCEMENT":
            [("mrf_invoked",0.90),("has_inap",0.82),("early_media",0.70),
             ("has_service_key",0.60),("has_200_ok",-0.45)],
    }

    w_list = weights.get(label, [("sip_msg_count", 0.20)])
    result = []
    for feat, score in w_list:
        val = features.get(feat, 0)
        result.append({
            "feature":     feat,
            "value":       val,
            "shap_score":  score,
            "direction":   "positive" if score > 0 else "negative",
            "description": _feature_description(feat, val),
        })
    return result


# ── Feature descriptions ───────────────────────────────────────

def _feature_description(feat: str, val) -> str:
    desc = {
        "is_487":           "SIP 487 Request Terminated received",
        "is_480":           "SIP 480 Temporarily Unavailable",
        "is_486":           "SIP 486 Busy Here",
        "is_488":           "SIP 488 Not Acceptable Here",
        "is_200":           "SIP 200 OK — call answered successfully",
        "has_cancel":       "CANCEL message present in dialog",
        "missing_cancel":   "No CANCEL despite 487 — not a user hangup",
        "has_180":          "180 Ringing — callee device was alerting",
        "has_183":          "183 Session Progress — early media / announcement",
        "has_200_ok":       "200 OK present in dialog",
        "has_bye":          "BYE present — clean call teardown",
        "early_media":      "Early media (183) indicates IN service or MRF",
        "missing_200_ok":   "No 200 OK — call was never answered",
        "missing_ringing":  "No 180/183 — never reached callee device",
        "time_to_failure_ms":"Time from INVITE to failure response",
        "is_timeout_pattern":"Failure >15 seconds — timer expiry",
        "is_immediate_fail":"Failure <500ms — immediate rejection",
        "q850_code":        "Q.850 PSTN cause code for termination",
        "q850_no_answer":   "Q.850: no answer from user (cause 18/19)",
        "q850_user_busy":   "Q.850: user busy (cause 17)",
        "q850_unreachable": "Q.850: subscriber absent (cause 20/27)",
        "charging_failed":  "Diameter CCR rejected — charging failure",
        "dia_failure_count":"Number of failed Diameter transactions",
        "ccr_initial_ok":   "CCR-Initial succeeded — charging allowed call",
        "has_ccr_term":     "CCR-Termination sent — call ended cleanly",
        "has_diameter":     "Diameter (online charging) was active",
        "inap_routing_fail":"INAP RouteSelectFailure — IN routing failed",
        "mrf_invoked":      "MRF/announcement invoked via INAP",
        "has_inap":         "IN service (INAP) was active for this call",
        "has_retransmission":"INVITE retransmitted — network instability",
        "invite_count":     "Number of INVITE attempts (retransmissions)",
        "flow_length":      "Number of signalling steps in call flow",
        "sip_msg_count":    "Total SIP messages in dialog",
        "dia_count":        "Total Diameter messages in session",
    }
    return desc.get(feat, feat.replace("_", " "))


# ── Feature vector builder ─────────────────────────────────────

def _features_to_vector(features: dict):
    """Convert feature dict to numpy array for model input."""
    row = [features.get(c, 0) for c in ML_FEATURE_COLS]
    return np.array(row, dtype=float).reshape(1, -1)
