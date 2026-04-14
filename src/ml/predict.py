# src/ml/predict.py
"""
RCA Prediction Pipeline

Runs the full inference pipeline on a single session:
  features → model.predict → label decode → SHAP explain

Also provides batch prediction across all sessions in a PCAP.
"""

import os
from functools import lru_cache

from loguru import logger

from src.config import cfg_path
from src.features.feature_engineer import (
    extract_features)
from src.explain.explainer import (
    explain_prediction, explain_rule_based)


MODEL_PATH   = cfg_path("model.path", "data/models/rca_model.pkl")
ENCODER_PATH = cfg_path("model.encoder_path", "data/models/label_encoder.pkl")


def predict_session(session: dict,
                    model=None,
                    encoder=None) -> dict:
    """
    Run full RCA prediction + explanation for one session.

    If model/encoder not provided, loads from disk.
    Falls back to rule-based explanation if model unavailable.

    Returns:
        Full explanation dict from explainer
    """
    # Extract features
    features = extract_features(session)

    # Try ML model first
    if model is None or encoder is None:
        loaded = _load_cached_artifacts()
        if loaded is None:
            logger.info(
                "No trained model found — using rule engine")
            return explain_rule_based(session, features)
        model, encoder = loaded

    try:
        result = explain_prediction(
            session, features, model, encoder)
        return result
    except Exception as e:
        logger.warning(f"ML prediction failed: {e}, falling back to rules")
        return explain_rule_based(session, features)


def predict_all_sessions(sessions: list,
                         model=None,
                         encoder=None) -> list:
    """
    Run predictions on all sessions.
    Returns list of explanation dicts.
    """
    if model is None or encoder is None:
        loaded = _load_cached_artifacts()
        if loaded is not None:
            model, encoder = loaded

    results = []
    for session in sessions:
        result = predict_session(session, model, encoder)
        results.append(result)

    logger.success(
        f"Predicted {len(results)} sessions")

    # Log label distribution
    from collections import Counter
    labels = Counter(r["rca_label"] for r in results)
    for label, count in labels.most_common():
        logger.info(f"  {label:30s}: {count}")

    return results


@lru_cache(maxsize=1)
def _load_cached_artifacts():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(ENCODER_PATH):
        return None

    import joblib

    model = joblib.load(MODEL_PATH)
    encoder = joblib.load(ENCODER_PATH)
    logger.debug("Loaded model artifacts from disk")
    return model, encoder
