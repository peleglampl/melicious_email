"""
ml_classifier.py — Loads the trained model and adds ml_phishing_score
to the features dict. Plugs into extract_features() as one extra signal.

If the model file doesn't exist, degrades gracefully (score = 0.0).
"""

from __future__ import annotations
import pickle
from pathlib import Path

_MODEL_PATH = Path(__file__).parent / "ml_model.pkl"
_pipeline = None


def _load_model():
    global _pipeline
    if _pipeline is None and _MODEL_PATH.exists():
        with open(_MODEL_PATH, "rb") as f:
            _pipeline = pickle.load(f)
    return _pipeline


def ml_phishing_score(subject: str, body: str | None) -> float:
    """
    Returns probability 0.0-1.0 that the email is phishing,
    based on subject + body text. Returns 0.0 if model not loaded.
    """
    pipeline = _load_model()
    if pipeline is None:
        return 0.0

    text = (subject + " " + (body or "")).strip()
    if not text:
        return 0.0

    try:
        prob = pipeline.predict_proba([text])[0][1]  # probability of class 1 (phishing)
        return round(float(prob), 3)
    except Exception:
        return 0.0
