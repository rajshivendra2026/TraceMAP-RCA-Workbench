# src/ml/synthetic.py
"""
Synthetic Training Data Generator — v2

WHY synthetic data is necessary
────────────────────────────────
The ML model needs labeled training examples for every RCA class.
Real PCAP files from a live network often contain only successful
calls (NORMAL_CALL), because that is the overwhelmingly common case.
Without failure examples, the model cannot learn to distinguish
NO_ANSWER_TIMEOUT from USER_ABORT or SUBSCRIBER_UNREACHABLE.

Synthetic data fills this gap by generating realistic feature
vectors for each failure scenario, based on telecom domain
knowledge of what each failure looks like in a real IMS trace.

Changes from v1
───────────────
1. pcap_source="synthetic" column added to every generated row.
   train.py uses this as the group key for GroupShuffleSplit, so
   synthetic rows are always split separately from real PCAP rows.
   This prevents the model from being evaluated on synthetic data
   that is structurally identical to its training data.

2. n_per_class from config.yaml training.synthetic_per_class.
   No more hardcoded 80 in multiple places.

3. Each scenario generator adds ±noise to numeric fields using
   _jitter(), so the synthetic distribution is not a perfect
   point cloud. This improves the model's decision boundaries.

4. generate_synthetic_dataset() accepts a real_df argument.
   When real labeled data is available, it is prepended and
   weighted higher than synthetic rows in the combined dataset.

How to read the scenario generators
────────────────────────────────────
Each make_*() function sets feature values that match what a
real IMS call with that failure type would produce.

Example — make_no_answer_timeout():
  - is_487 = 1                (final response is 487)
  - has_180 = 1               (180 Ringing was received — callee alerted)
  - has_cancel = 0            (no CANCEL — caller did not hang up)
  - missing_cancel = 1        (absence of CANCEL is the key signal)
  - is_timeout_pattern = 1    (time_to_failure_ms > 15 000)
  - q850_no_answer = 1        (Q.850 cause 19 in Reason header)

These features collectively distinguish NO_ANSWER_TIMEOUT from
USER_ABORT (which has has_cancel=1) and SERVICE_TIMEOUT (which
has has_183=1 instead of has_180=1).
"""

import random
from typing import Optional

import pandas as pd
from loguru import logger

from src.config import cfg


# ── Base feature template ─────────────────────────────────────
# Represents a typical successful IMS call with online charging.
# Each scenario generator starts from this and overrides the
# fields that differ for that failure type.

_BASE: dict = {
    # SIP response
    "sip_code":           200,
    "sip_1xx":            0,
    "sip_2xx":            1,
    "sip_4xx":            0,
    "sip_5xx":            0,
    "is_480":             0,
    "is_487":             0,
    "is_488":             0,
    "is_486":             0,
    "is_408":             0,
    "is_503":             0,
    "is_200":             1,

    # SIP flow
    "has_invite":         1,
    "has_cancel":         0,
    "has_bye":            1,
    "has_180":            1,
    "has_183":            0,
    "has_200_ok":         1,
    "has_prack":          0,
    "early_media":        0,
    "invite_count":       1,
    "sip_msg_count":      8,
    "flow_length":        6,
    "known_flow":         1,

    # Absence flags
    "missing_ringing":    0,
    "missing_cancel":     0,
    "missing_200_ok":     0,
    "missing_bye":        0,

    # Timing
    "duration_ms":        20000.0,
    "time_to_failure_ms": 0.0,
    "is_immediate_fail":  0,
    "is_fast_fail":       0,
    "is_timeout_pattern": 0,

    # Q.850
    "q850_code":          16,   # 16 = normal clearing
    "q850_user_busy":     0,
    "q850_no_answer":     0,
    "q850_unreachable":   0,
    "q850_rejected":      0,
    "q850_network_fail":  0,
    "q850_normal":        1,

    # Diameter
    "dia_count":          4,
    "dia_failure_count":  0,
    "has_ccr_initial":    1,
    "has_ccr_term":       1,
    "ccr_initial_ok":     1,
    "charging_failed":    0,
    "sub_unreachable_dia":0,
    "auth_failed_dia":    0,
    "has_diameter":       1,

    # INAP
    "inap_count":         0,
    "mrf_invoked":        0,
    "inap_routing_fail":  0,
    "inap_service_logic": 0,
    "inap_release_call":  0,
    "has_service_key":    0,
    "has_inap":           0,

    # Retransmission
    "has_retransmission": 0,
}


# ══════════════════════════════════════════════════════════════
#  SCENARIO GENERATORS
#  Each returns a list of n feature dicts for that RCA class.
# ══════════════════════════════════════════════════════════════

def make_normal_call(n: int = 1, rng: random.Random = None) -> list:
    """
    Successful IMS call with online charging.
    Flow: INVITE → 100 → 180 → 200 → ACK → BYE
    """
    rng = rng or random.Random()
    rows = []
    for _ in range(n):
        r = _base()
        r.update({
            "duration_ms":    _jitter(rng, 20000, 0.5),
            "sip_msg_count":  rng.randint(6, 14),
            "invite_count":   rng.choices([1, 2], weights=[80, 20])[0],
            "has_retransmission": 0,
            "rca_label":      "NORMAL_CALL",
        })
        # Some normal calls have retransmissions (invite_count > 1)
        if r["invite_count"] > 1:
            r["has_retransmission"] = 1
            r["sip_msg_count"] += r["invite_count"] - 1
        rows.append(r)
    return rows


def make_user_abort(n: int = 1, rng: random.Random = None) -> list:
    """
    Caller pressed end before the callee answered.
    Flow: INVITE → 100 → [180] → CANCEL → 487 → ACK

    Key signals:
      has_cancel = 1    (CANCEL message present)
      is_487 = 1        (terminated after CANCEL)
      missing_cancel = 0  (CANCEL IS there — absence flag is False)
    """
    rng = rng or random.Random()
    rows = []
    for _ in range(n):
        ttf = _jitter(rng, rng.uniform(2000, 14000))
        has_180 = rng.choices([0, 1], weights=[30, 70])[0]
        r = _base()
        r.update({
            "sip_code":           487,
            "sip_2xx":            0,
            "sip_4xx":            1,
            "is_487":             1,
            "is_200":             0,
            "has_cancel":         1,
            "has_bye":            0,
            "has_180":            has_180,
            "has_200_ok":         0,
            "missing_200_ok":     1,
            "missing_cancel":     0,     # CANCEL IS present
            "missing_ringing":    0 if has_180 else 1,
            "duration_ms":        ttf,
            "time_to_failure_ms": ttf,
            "is_fast_fail":       1 if ttf < 5000 else 0,
            "is_timeout_pattern": 0,
            "q850_code":          16,    # normal clearing (user hung up)
            "q850_normal":        1,
            "q850_no_answer":     0,
            "dia_count":          rng.choice([0, 2, 2, 4]),
            "has_ccr_term":       0,     # charging was not terminated cleanly
            "sip_msg_count":      rng.randint(5, 9),
            "flow_length":        rng.randint(4, 6),
            "known_flow":         0,
            "rca_label":          "USER_ABORT",
        })
        r["has_diameter"]  = 1 if r["dia_count"] > 0 else 0
        r["has_ccr_initial"] = 1 if r["dia_count"] > 0 else 0
        rows.append(r)
    return rows


def make_no_answer_timeout(n: int = 1, rng: random.Random = None) -> list:
    """
    Callee's phone rang but they never answered. The network
    timer expired and sent a 487.
    Flow: INVITE → 100 → 180 → 487 → ACK

    Key signals:
      has_180 = 1         (callee was alerted — phone rang)
      has_cancel = 0      (caller did NOT hang up)
      missing_cancel = 1  (absence of CANCEL is the defining signal)
      is_timeout_pattern = 1 (time_to_failure_ms > 15 000)
      q850_no_answer = 1  (Q.850 cause 19)
    """
    rng = rng or random.Random()
    rows = []
    for _ in range(n):
        # No-answer timers are typically 15–45 seconds
        ttf = _jitter(rng, rng.uniform(18000, 45000))
        r = _base()
        r.update({
            "sip_code":           487,
            "sip_2xx":            0,
            "sip_4xx":            1,
            "is_487":             1,
            "is_200":             0,
            "has_cancel":         0,
            "has_bye":            0,
            "has_180":            1,
            "has_183":            0,
            "has_200_ok":         0,
            "missing_200_ok":     1,
            "missing_cancel":     1,     # ← key distinguishing feature
            "missing_ringing":    0,
            "duration_ms":        ttf,
            "time_to_failure_ms": ttf,
            "is_timeout_pattern": 1,     # > 15 000 ms
            "is_fast_fail":       0,
            "q850_code":          19,    # no answer from user
            "q850_no_answer":     1,
            "q850_normal":        0,
            "dia_count":          rng.choice([2, 2, 4]),
            "has_ccr_term":       0,
            "sip_msg_count":      rng.randint(4, 7),
            "flow_length":        4,
            "known_flow":         1,
            "rca_label":          "NO_ANSWER_TIMEOUT",
        })
        r["has_diameter"]   = 1 if r["dia_count"] > 0 else 0
        r["has_ccr_initial"]= 1 if r["dia_count"] > 0 else 0
        rows.append(r)
    return rows


def make_service_timeout(n: int = 1, rng: random.Random = None) -> list:
    """
    IN service or MRF was active (183 early media), then timed out.
    Flow: INVITE → 100 → 183 → 487 → ACK

    Key signals:
      has_183 = 1       (early media / IN service active)
      early_media = 1
      has_cancel = 0    (not a user hangup)
      has_inap = 1      (IN service was involved)
    """
    rng = rng or random.Random()
    rows = []
    for _ in range(n):
        ttf = _jitter(rng, rng.uniform(10000, 30000))
        r = _base()
        r.update({
            "sip_code":           487,
            "sip_2xx":            0,
            "sip_4xx":            1,
            "is_487":             1,
            "is_200":             0,
            "has_cancel":         0,
            "has_bye":            0,
            "has_180":            0,
            "has_183":            1,
            "early_media":        1,
            "has_200_ok":         0,
            "missing_200_ok":     1,
            "missing_cancel":     1,
            "missing_ringing":    0,
            "duration_ms":        ttf,
            "time_to_failure_ms": ttf,
            "is_timeout_pattern": 1 if ttf > 15000 else 0,
            "is_fast_fail":       0,
            "q850_code":          -1,
            "q850_normal":        0,
            "inap_count":         rng.randint(2, 6),
            "inap_service_logic": 1,
            "inap_release_call":  rng.choice([0, 1]),
            "has_service_key":    1,
            "has_inap":           1,
            "dia_count":          rng.choice([2, 2, 4]),
            "has_ccr_term":       0,
            "sip_msg_count":      rng.randint(5, 10),
            "flow_length":        4,
            "known_flow":         1,
            "rca_label":          "SERVICE_TIMEOUT",
        })
        r["has_diameter"]   = 1 if r["dia_count"] > 0 else 0
        r["has_ccr_initial"]= 1 if r["dia_count"] > 0 else 0
        rows.append(r)
    return rows


def make_subscriber_unreachable(n: int = 1, rng: random.Random = None) -> list:
    """
    Callee's device is powered off, unregistered, or outside coverage.
    Flow: INVITE → 100 → 480

    Key signals:
      is_480 = 1          (480 Temporarily Unavailable)
      missing_ringing = 1 (never reached callee device)
      is_immediate_fail = 1 (fast rejection from HSS/registrar)
      q850_unreachable = 1 (Q.850 cause 20: subscriber absent)
    """
    rng = rng or random.Random()
    rows = []
    for _ in range(n):
        # Immediate rejection — HSS knows subscriber is not registered
        ttf = _jitter(rng, rng.uniform(100, 2000))
        r = _base()
        r.update({
            "sip_code":           480,
            "sip_2xx":            0,
            "sip_4xx":            1,
            "is_480":             1,
            "is_200":             0,
            "has_cancel":         0,
            "has_bye":            0,
            "has_180":            0,
            "has_200_ok":         0,
            "missing_200_ok":     1,
            "missing_ringing":    1,
            "missing_cancel":     0,
            "duration_ms":        ttf,
            "time_to_failure_ms": ttf,
            "is_immediate_fail":  1 if ttf < 500 else 0,
            "is_fast_fail":       1 if 500 <= ttf < 5000 else 0,
            "is_timeout_pattern": 0,
            "q850_code":          20,    # subscriber absent
            "q850_unreachable":   1,
            "q850_normal":        0,
            "dia_count":          rng.choice([0, 0, 2]),
            "has_ccr_initial":    0,
            "has_ccr_term":       0,
            "ccr_initial_ok":     0,
            "has_diameter":       0,
            # HSS may return a Location-Info failure (Cx, cmd 302)
            "sub_unreachable_dia":rng.choice([0, 0, 1]),
            "sip_msg_count":      rng.randint(2, 4),
            "flow_length":        3,
            "known_flow":         1,
            "rca_label":          "SUBSCRIBER_UNREACHABLE",
        })
        rows.append(r)
    return rows


def make_user_busy(n: int = 1, rng: random.Random = None) -> list:
    """
    Callee is already on another call.
    Flow: INVITE → 100 → 486

    Key signals:
      is_486 = 1        (486 Busy Here)
      q850_user_busy = 1 (Q.850 cause 17)
      is_fast_fail = 1  (callee UE responds quickly)
    """
    rng = rng or random.Random()
    rows = []
    for _ in range(n):
        ttf = _jitter(rng, rng.uniform(300, 3000))
        r = _base()
        r.update({
            "sip_code":           486,
            "sip_2xx":            0,
            "sip_4xx":            1,
            "is_486":             1,
            "is_200":             0,
            "has_cancel":         0,
            "has_bye":            0,
            "has_180":            0,
            "has_200_ok":         0,
            "missing_200_ok":     1,
            "missing_ringing":    1,
            "duration_ms":        ttf,
            "time_to_failure_ms": ttf,
            "is_fast_fail":       1,
            "is_timeout_pattern": 0,
            "q850_code":          17,    # user busy
            "q850_user_busy":     1,
            "q850_normal":        0,
            "dia_count":          rng.choice([0, 0, 2]),
            "has_ccr_initial":    0,
            "has_ccr_term":       0,
            "has_diameter":       0,
            "sip_msg_count":      rng.randint(3, 5),
            "flow_length":        3,
            "known_flow":         1,
            "rca_label":          "USER_BUSY",
        })
        rows.append(r)
    return rows


def make_codec_mismatch(n: int = 1, rng: random.Random = None) -> list:
    """
    SDP negotiation failed — incompatible codec or media parameters.
    Flow: INVITE → 100 → 488

    Key signals:
      is_488 = 1         (488 Not Acceptable Here)
      is_immediate_fail  (SDP rejection is near-instant)
      No Diameter failure (charging was not the issue)
    """
    rng = rng or random.Random()
    rows = []
    for _ in range(n):
        ttf = _jitter(rng, rng.uniform(100, 800))
        r = _base()
        r.update({
            "sip_code":           488,
            "sip_2xx":            0,
            "sip_4xx":            1,
            "is_488":             1,
            "is_200":             0,
            "has_cancel":         0,
            "has_bye":            0,
            "has_180":            0,
            "has_200_ok":         0,
            "missing_200_ok":     1,
            "missing_ringing":    1,
            "duration_ms":        ttf,
            "time_to_failure_ms": ttf,
            "is_immediate_fail":  1,
            "is_fast_fail":       0,
            "q850_code":          88,    # incompatible destination
            "q850_normal":        0,
            "dia_count":          0,
            "has_ccr_initial":    0,
            "has_ccr_term":       0,
            "has_diameter":       0,
            "sip_msg_count":      rng.randint(2, 4),
            "flow_length":        3,
            "known_flow":         0,
            "rca_label":          "CODEC_MISMATCH",
        })
        rows.append(r)
    return rows


def make_charging_failure(n: int = 1, rng: random.Random = None) -> list:
    """
    Online charging system (OCS) rejected the session.
    The call was blocked at the Ro interface, not the SIP layer.

    Key signals:
      charging_failed = 1    (Diameter CCR-Initial returned failure)
      dia_failure_count > 0
      ccr_initial_ok = 0     (CCR-Initial was NOT successful)
      has_ccr_term = 0       (no termination — session was never established)
    """
    rng = rng or random.Random()
    rows = []
    for _ in range(n):
        ttf = _jitter(rng, rng.uniform(500, 3000))
        dia_count = rng.randint(2, 6)
        r = _base()
        r.update({
            "sip_code":           403,   # 403 or 402 from SIP perspective
            "sip_2xx":            0,
            "sip_4xx":            1,
            "is_200":             0,
            "has_cancel":         0,
            "has_bye":            0,
            "has_180":            0,
            "has_200_ok":         0,
            "missing_200_ok":     1,
            "missing_ringing":    1,
            "duration_ms":        ttf,
            "time_to_failure_ms": ttf,
            "is_fast_fail":       1,
            "q850_code":          -1,
            "q850_normal":        0,
            "dia_count":          dia_count,
            "dia_failure_count":  rng.randint(1, max(1, dia_count // 2)),
            "has_ccr_initial":    1,
            "has_ccr_term":       0,
            "ccr_initial_ok":     0,     # ← key signal: CCR-I failed
            "charging_failed":    1,
            "has_diameter":       1,
            "sip_msg_count":      rng.randint(3, 6),
            "flow_length":        3,
            "known_flow":         0,
            "rca_label":          "CHARGING_FAILURE",
        })
        rows.append(r)
    return rows


def make_routing_failure(n: int = 1, rng: random.Random = None) -> list:
    """
    INAP RouteSelectFailure — the IN platform could not route the call.
    Flow: INVITE → 100 → 183 → 487 (via INAP ReleaseCall)

    Key signals:
      inap_routing_fail = 1  (RouteSelectFailure opcode)
      inap_release_call = 1  (ReleaseCall sent to SSF)
      has_inap = 1
    """
    rng = rng or random.Random()
    rows = []
    for _ in range(n):
        ttf = _jitter(rng, rng.uniform(1000, 8000))
        r = _base()
        r.update({
            "sip_code":           487,
            "sip_2xx":            0,
            "sip_4xx":            1,
            "is_487":             1,
            "is_200":             0,
            "has_cancel":         0,
            "has_bye":            0,
            "has_183":            rng.choice([0, 1]),
            "early_media":        0,
            "has_200_ok":         0,
            "missing_200_ok":     1,
            "missing_cancel":     1,
            "duration_ms":        ttf,
            "time_to_failure_ms": ttf,
            "is_fast_fail":       1 if ttf < 5000 else 0,
            "q850_code":          -1,
            "q850_normal":        0,
            "inap_count":         rng.randint(2, 6),
            "inap_routing_fail":  1,
            "inap_service_logic": 1,
            "inap_release_call":  1,
            "has_service_key":    1,
            "has_inap":           1,
            "dia_count":          rng.choice([0, 2, 2]),
            "has_ccr_term":       0,
            "sip_msg_count":      rng.randint(4, 8),
            "flow_length":        rng.randint(3, 5),
            "rca_label":          "ROUTING_FAILURE",
        })
        r["has_diameter"]   = 1 if r["dia_count"] > 0 else 0
        r["has_ccr_initial"]= 1 if r["dia_count"] > 0 else 0
        rows.append(r)
    return rows


def make_announcement(n: int = 1, rng: random.Random = None) -> list:
    """
    MRF announcement was played (VVAS, CDIV announcement, etc.).
    An INAP ConnectToResource/PlayAnnouncement was invoked.

    Key signals:
      mrf_invoked = 1    (ConnectToResource or PlayAnnouncement opcode)
      early_media = 1    (183 carries the audio channel)
      has_inap = 1
    """
    rng = rng or random.Random()
    rows = []
    for _ in range(n):
        dur = _jitter(rng, rng.uniform(8000, 30000))
        r = _base()
        r.update({
            "has_183":            1,
            "early_media":        1,
            "has_200_ok":         rng.choice([0, 1]),
            "is_200":             rng.choice([0, 1]),
            "sip_2xx":            rng.choice([0, 1]),
            "duration_ms":        dur,
            "inap_count":         rng.randint(3, 8),
            "mrf_invoked":        1,
            "inap_service_logic": 1,
            "inap_release_call":  rng.choice([0, 1]),
            "has_service_key":    1,
            "has_inap":           1,
            "dia_count":          rng.choice([2, 4, 4]),
            "has_diameter":       1,
            "has_ccr_initial":    1,
            "has_ccr_term":       rng.choice([0, 1]),
            "ccr_initial_ok":     1,
            "sip_msg_count":      rng.randint(6, 14),
            "flow_length":        rng.randint(4, 7),
            "rca_label":          "ANNOUNCEMENT",
        })
        rows.append(r)
    return rows


# ══════════════════════════════════════════════════════════════
#  MAIN GENERATOR
# ══════════════════════════════════════════════════════════════

# Maps RCA label → generator function
_GENERATORS = {
    "NORMAL_CALL":           make_normal_call,
    "USER_ABORT":            make_user_abort,
    "NO_ANSWER_TIMEOUT":     make_no_answer_timeout,
    "SERVICE_TIMEOUT":       make_service_timeout,
    "SUBSCRIBER_UNREACHABLE":make_subscriber_unreachable,
    "USER_BUSY":             make_user_busy,
    "CODEC_MISMATCH":        make_codec_mismatch,
    "CHARGING_FAILURE":      make_charging_failure,
    "ROUTING_FAILURE":       make_routing_failure,
    "ANNOUNCEMENT":          make_announcement,
}


def generate_synthetic_dataset(
        n_per_class: Optional[int] = None,
        real_df:     Optional[pd.DataFrame] = None,
        random_seed: int = 42,
) -> pd.DataFrame:
    """
    Generate a synthetic training dataset covering all RCA classes.

    Args:
        n_per_class: samples per class.
                     Defaults to config.yaml training.synthetic_per_class.
        real_df:     if provided, real labeled rows are prepended to
                     the synthetic data. Only rows with known labels
                     (not "UNKNOWN") are included.
        random_seed: seed for reproducibility.

    Returns:
        Shuffled DataFrame with ML features, rca_label column,
        and pcap_source="synthetic" for all generated rows.
        Real rows (if any) keep their original pcap_source value.
    """
    if n_per_class is None:
        n_per_class = cfg("training.synthetic_per_class", 80)

    rng = random.Random(random_seed)

    logger.info(
        f"Generating synthetic data: "
        f"{n_per_class} samples × {len(_GENERATORS)} classes"
    )

    all_rows = []

    for label, generator in _GENERATORS.items():
        rows = generator(n=n_per_class, rng=rng)
        # Mark every synthetic row with pcap_source="synthetic"
        # so train.py can keep them together in the group split
        for row in rows:
            row["pcap_source"] = "synthetic"
        all_rows.extend(rows)
        logger.info(f"  {label:30s}: {len(rows)} rows")

    df_synth = pd.DataFrame(all_rows)

    # ── Prepend real data if available ────────────────────────
    if real_df is not None and not real_df.empty:
        # Only include rows with a known, actionable label
        known_mask = (
            real_df["rca_label"].notna()
            & (real_df["rca_label"] != "UNKNOWN")
        )
        real_known = real_df[known_mask].copy()

        if not real_known.empty:
            # Real data does not get pcap_source="synthetic"
            # It keeps whatever pcap_source pipeline.py set
            df_synth = pd.concat(
                [real_known, df_synth],
                ignore_index=True,
            )
            logger.info(
                f"Prepended {len(real_known)} real PCAP rows "
                f"(from {real_known['pcap_source'].nunique()} sources)"
            )
        else:
            logger.info(
                "No real rows with known labels to prepend"
            )

    # ── Shuffle ───────────────────────────────────────────────
    df_synth = df_synth.sample(
        frac=1, random_state=random_seed
    ).reset_index(drop=True)

    # ── Summary ───────────────────────────────────────────────
    n_synthetic = (df_synth["pcap_source"] == "synthetic").sum()
    n_real      = len(df_synth) - n_synthetic
    logger.success(
        f"Dataset ready: {len(df_synth)} total rows  "
        f"({n_real} real + {n_synthetic} synthetic)  "
        f"{df_synth['rca_label'].nunique()} classes"
    )

    return df_synth


# ══════════════════════════════════════════════════════════════
#  PRIVATE HELPERS
# ══════════════════════════════════════════════════════════════

def _base() -> dict:
    """Return a fresh copy of the base feature template."""
    return dict(_BASE)


def _jitter(rng: random.Random,
            val: float,
            pct: float = 0.15) -> float:
    """
    Add ±pct% random noise to a numeric value.

    Prevents the synthetic distribution from being a perfect
    point cloud, which would cause the model to learn
    overly sharp decision boundaries that don't generalise.
    """
    factor = 1.0 + rng.uniform(-pct, pct)
    return round(val * factor, 2)
