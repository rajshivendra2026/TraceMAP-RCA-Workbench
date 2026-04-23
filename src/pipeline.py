# src/pipeline.py
"""
Training Data Pipeline — v2

Processes one or more PCAP files and builds a combined, labeled
feature DataFrame ready for XGBoost training.

Changes from v1
───────────────
1. pcap_source column — every row in the output DataFrame carries
   the source PCAP filename. train.py uses this as the group key
   for GroupShuffleSplit so sessions from the same PCAP are never
   split across train and test.

2. All directory paths from config.yaml data.* — no more hardcoded
   "data/raw_pcaps", "data/features" etc. scattered in code.

3. process_pcap() accepts an optional runner argument so the
   pipeline can be unit-tested with a MockRunner without needing
   real PCAP files or a tshark binary.

4. Error handling per-PCAP — one bad file does not abort the
   entire pipeline. The error is logged and the file is skipped.

5. get_label_distribution() returns a sorted dict so the caller
   can log it consistently without reimplementing the sort.

Usage
─────
    # Process all PCAPs in data/raw_pcaps/
    from src.pipeline import process_all_pcaps
    df = process_all_pcaps()

    # Process a single PCAP
    from src.pipeline import process_pcap
    sessions = process_pcap("data/raw_pcaps/Trace-05.pcap")

    # Build the combined training dataset
    from src.pipeline import build_training_dataframe
    df = build_training_dataframe()
"""

import json
import os
from collections import Counter
from pathlib import Path

import pandas as pd
from loguru import logger

from src.config import cfg, cfg_path
from src.parser.pcap_loader           import load_pcap
from src.parser.tshark_runner         import TSharkRunner
from src.correlation.session_builder  import build_sessions
from src.features.feature_engineer    import (
    extract_features,
    build_feature_dataframe,
    save_features,
    ML_FEATURE_COLS,
)
from src.rules.rca_rules              import label_sessions


# ══════════════════════════════════════════════════════════════
#  SINGLE-PCAP PROCESSING
# ══════════════════════════════════════════════════════════════

def process_pcap(
        pcap_path: str,
        runner:    TSharkRunner = None,
        raise_on_error: bool = False,
) -> list:
    """
    Run the full parse → correlate → label pipeline on one PCAP.

    Args:
        pcap_path: path to .pcap or .pcapng file
        runner:    TSharkRunner instance (injectable for testing).
                   If None a real runner is constructed from config.
        raise_on_error: re-raise failures instead of returning an empty
                   session list. Use this for workflows that must not
                   mark a broken trace as successfully processed.

    Returns:
        List of labeled session dicts.
        Each session has an "rca" key with the rule-engine output
        and a "pcap_source" key with the PCAP filename (stem only,
        e.g. "Trace-05" from "Trace-05.pcap").

    Does not raise on parse errors by default — logs and returns []
    so process_all_pcaps() can continue to the next file.
    """
    pcap_name = Path(pcap_path).name
    pcap_stem = Path(pcap_path).stem   # "Trace-05" from "Trace-05.pcap"

    try:
        logger.info(f"Processing: {pcap_name}")

        parsed   = load_pcap(pcap_path, runner=runner)
        sessions = build_sessions(parsed)
        sessions = label_sessions(sessions)
        from src.autonomous.engine import AutonomousRCAEngine
        from src.intelligence.learning_loop import run_learning_cycle
        autonomous = AutonomousRCAEngine()

        # Attach pcap_source to every session so the feature
        # DataFrame knows which PCAP each row came from.
        for s in sessions:
            s["pcap_source"] = pcap_stem

        learning = run_learning_cycle(
            sessions,
            compact=bool(cfg("learning.compact_on_batch", True)),
            export_skills=bool(cfg("learning.export_skill_on_batch", False)),
            autonomous_engine=autonomous,
        )
        sessions = learning["sessions"]
        learning_metrics = learning.get("metrics", {})
        for s in sessions:
            s["learning_metrics"] = dict(learning_metrics)

        # Log per-PCAP label distribution
        from collections import Counter
        label_dist = Counter(
            s["rca"]["rca_label"] for s in sessions
        )
        logger.info(
            f"  {pcap_name}: {len(sessions)} sessions  "
            + "  ".join(
                f"{lbl}={cnt}"
                for lbl, cnt in label_dist.most_common()
            )
        )

        return sessions

    except Exception as exc:
        logger.error(
            f"Failed to process {pcap_name}: {exc}"
        )
        logger.debug(f"Traceback:", exc_info=True)
        if raise_on_error:
            raise
        return []


# ══════════════════════════════════════════════════════════════
#  MULTI-PCAP PIPELINE
# ══════════════════════════════════════════════════════════════

def process_all_pcaps(
        pcap_dir: str = None,
        runner:   TSharkRunner = None,
) -> pd.DataFrame:
    """
    Process every .pcap / .pcapng file in pcap_dir and return
    a combined feature DataFrame with rca_label and pcap_source.

    Args:
        pcap_dir: directory to search for PCAP files.
                  Defaults to config.yaml data.raw_pcaps.
        runner:   TSharkRunner (injectable for testing).

    Returns:
        DataFrame with:
          - One row per session across all PCAPs
          - All ML_FEATURE_COLS columns
          - "rca_label"   column: string class label from rule engine
          - "pcap_source" column: source PCAP stem (e.g. "Trace-05")

        Returns an empty DataFrame (not an error) if no PCAPs found.
    """
    if pcap_dir is None:
        pcap_dir = cfg_path("data.raw_pcaps", "data/raw_pcaps")

    # Collect all PCAP files
    pcap_dir_path = Path(pcap_dir)
    if not pcap_dir_path.exists():
        logger.warning(f"PCAP directory not found: {pcap_dir}")
        return pd.DataFrame()

    pcap_files = sorted(
        list(pcap_dir_path.glob("*.pcap"))
        + list(pcap_dir_path.glob("*.pcapng"))
    )

    if not pcap_files:
        logger.warning(f"No .pcap/.pcapng files found in {pcap_dir}")
        return pd.DataFrame()

    logger.info(
        f"Found {len(pcap_files)} PCAP file(s) in {pcap_dir}:"
    )
    for p in pcap_files:
        logger.info(f"  {p.name}  ({p.stat().st_size / 1024:.1f} KB)")

    # Process each PCAP
    all_sessions: list = []
    for pcap_path in pcap_files:
        sessions = process_pcap(str(pcap_path), runner=runner)
        all_sessions.extend(sessions)

    if not all_sessions:
        logger.error(
            "No sessions extracted from any PCAP file. "
            "Check that tshark is installed and the PCAPs are valid."
        )
        return pd.DataFrame()

    logger.success(
        f"Total sessions across all PCAPs: {len(all_sessions)}"
    )

    # Build feature DataFrame
    df = _sessions_to_dataframe(all_sessions)

    # Save combined dataset
    _save_combined(df, all_sessions)

    # Log overall label distribution
    logger.info("Overall label distribution:")
    for label, count in get_label_distribution(df).items():
        bar = "█" * min(count, 50)
        logger.info(f"  {label:30s} {count:4d}  {bar}")

    return df


# ══════════════════════════════════════════════════════════════
#  TRAINING DATAFRAME BUILDER
# ══════════════════════════════════════════════════════════════

def build_training_dataframe(
        pcap_dir:   str = None,
        runner:     TSharkRunner = None,
) -> pd.DataFrame:
    """
    Build a DataFrame from all real PCAPs, ready to be passed to
    train.py (optionally combined with synthetic data there).

    This is the function called by train.py (project root).

    Returns:
        DataFrame with ML features, rca_label, and pcap_source.
        May be empty if no PCAPs are available — callers should
        check before proceeding.
    """
    return process_all_pcaps(pcap_dir=pcap_dir, runner=runner)


def audit_pcap_corpus(
        pcap_dir: str,
        recursive: bool = True,
        limit: int | None = None,
        runner: TSharkRunner = None,
) -> list[dict]:
    """
    Build a compact audit summary for a PCAP corpus.

    The goal is to rank traces with the highest UNKNOWN footprint so parser/RCA
    improvements can be prioritized on real data.
    """
    root = Path(pcap_dir)
    if not root.exists():
        logger.warning(f"PCAP audit directory not found: {pcap_dir}")
        return []

    if recursive:
        pcap_files = sorted(
            [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in {".pcap", ".pcapng"}]
        )
    else:
        pcap_files = sorted(
            list(root.glob("*.pcap")) + list(root.glob("*.pcapng"))
        )

    if limit is not None:
        pcap_files = pcap_files[: max(0, int(limit))]

    summaries: list[dict] = []
    for pcap_path in pcap_files:
        sessions = process_pcap(str(pcap_path), runner=runner)
        label_dist = Counter(s["rca"]["rca_label"] for s in sessions if s.get("rca"))
        summaries.append(
            {
                "pcap": str(pcap_path),
                "sessions": len(sessions),
                "unknown_sessions": int(label_dist.get("UNKNOWN", 0)),
                "labels": dict(label_dist),
                "protocols": sorted({p for s in sessions for p in s.get("protocols", [])}),
                "technologies": sorted({t for s in sessions for t in s.get("technologies", [])}),
            }
        )

    summaries.sort(key=lambda item: (item["unknown_sessions"], item["sessions"]), reverse=True)
    return summaries


# ══════════════════════════════════════════════════════════════
#  LABEL DISTRIBUTION HELPER
# ══════════════════════════════════════════════════════════════

def get_label_distribution(df: pd.DataFrame) -> dict:
    """
    Return {rca_label: count} sorted by count descending.

    Args:
        df: DataFrame with an "rca_label" column.

    Returns:
        OrderedDict sorted by count descending.
        Returns empty dict if "rca_label" column is missing.
    """
    if "rca_label" not in df.columns:
        return {}
    counts = df["rca_label"].value_counts()
    return dict(counts)


# ══════════════════════════════════════════════════════════════
#  PRIVATE HELPERS
# ══════════════════════════════════════════════════════════════

def _sessions_to_dataframe(sessions: list) -> pd.DataFrame:
    """
    Extract features from every session and assemble a DataFrame.

    Adds:
      - rca_label   from session["rca"]["rca_label"]
      - pcap_source from session["pcap_source"]

    Rows that fail feature extraction are skipped with a warning.
    """
    rows = []
    skipped = 0

    for session in sessions:
        try:
            feats = extract_features(session)

            # Attach label and source
            feats["rca_label"]   = (
                session.get("rca", {}).get("rca_label", "UNKNOWN")
            )
            feats["pcap_source"] = session.get("pcap_source", "unknown")

            rows.append(feats)

        except Exception as exc:
            logger.warning(
                f"Feature extraction failed for session "
                f"{session.get('session_id', '?')[:30]}: {exc}"
            )
            skipped += 1

    if skipped:
        logger.warning(
            f"Skipped {skipped} sessions due to feature extraction errors"
        )

    df = pd.DataFrame(rows)

    logger.info(
        f"Feature matrix: {df.shape[0]} rows × {df.shape[1]} columns"
    )
    return df


def _save_combined(df: pd.DataFrame, sessions: list) -> None:
    """
    Persist the combined feature DataFrame and session list to disk.
    Paths come from config.yaml data.* so nothing is hardcoded.
    """
    features_dir = cfg_path("data.features", "data/features")
    parsed_dir   = cfg_path("data.parsed",   "data/parsed")

    os.makedirs(features_dir, exist_ok=True)
    os.makedirs(parsed_dir,   exist_ok=True)

    # Save feature CSV
    features_path = os.path.join(features_dir, "all_features.csv")
    df.to_csv(features_path, index=False)
    logger.info(f"Features saved → {features_path}")

    # Save sessions JSON (without large message lists to keep size manageable)
    sessions_path = os.path.join(parsed_dir, "all_sessions.json")
    slim_sessions = []
    for s in sessions:
        slim_sessions.append({
            "session_id":      s.get("session_id"),
            "call_id":         s.get("call_id"),
            "pcap_source":     s.get("pcap_source"),
            "calling":         s.get("calling"),
            "called":          s.get("called"),
            "flow":            s.get("flow"),
            "final_sip_code":  s.get("final_sip_code"),
            "duration_ms":     s.get("duration_ms"),
            "protocols":       s.get("protocols"),
            "dia_correlation": s.get("dia_correlation"),
            "rca":             s.get("rca", {}),
        })

    with open(sessions_path, "w", encoding="utf-8") as f:
        json.dump(slim_sessions, f, indent=2, default=str)
    logger.info(
        f"Session summaries saved → {sessions_path} "
        f"({len(slim_sessions)} entries)"
    )
