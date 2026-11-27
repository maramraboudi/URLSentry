import json
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd

from src.features.url_features import extract_url_features


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = PROJECT_ROOT / "models" / "best_model.joblib"
CONFIG_PATH = PROJECT_ROOT / "models" / "model_config.json"


@lru_cache(maxsize=1)
def load_artifacts():
    """Load the model and its deployment configuration once."""

    if not MODEL_PATH.exists():
        raise FileNotFoundError("Trained model not found.")

    if not CONFIG_PATH.exists():
        raise FileNotFoundError("Model configuration not found.")

    model = joblib.load(MODEL_PATH)

    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        config = json.load(file)

    required_features = config["features"]

    if not required_features:
        raise ValueError("Model feature configuration is empty.")

    return model, config


def validate_url(url):
    """Validate an HTTP or HTTPS URL without visiting it."""

    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if len(url) > 2048:
        raise ValueError("URL is too long.")

    if any(character.isspace() for character in url):
        raise ValueError("URL must not contain whitespace.")

    try:
        parsed = urlsplit(url)

        # Force validation of the port if one is supplied.
        _ = parsed.port

    except ValueError as error:
        raise ValueError("Invalid URL format.") from error

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are accepted.")

    if not parsed.hostname:
        raise ValueError("URL must contain a hostname.")

    return url


def predict_url(url):
    """Return a phishing prediction for a supplied URL."""

    url = validate_url(url)

    model, config = load_artifacts()

    # Extract the exact feature set used during training.
    features = extract_url_features(url)

    feature_columns = config["features"]

    missing_features = [
        feature
        for feature in feature_columns
        if feature not in features
    ]

    if missing_features:
        raise ValueError(
            f"Missing model features: {missing_features}"
        )

    feature_frame = pd.DataFrame(
        [[features[name] for name in feature_columns]],
        columns=feature_columns,
    )

    phishing_score = float(
        model.predict_proba(feature_frame)[0][1]
    )

    threshold = float(config["threshold"])

    is_phishing = phishing_score >= threshold

    # These are descriptive score bands, not calibrated risk estimates.
    if phishing_score >= max(0.75, threshold):
        risk_level = "high"
    elif is_phishing:
        risk_level = "elevated"
    else:
        risk_level = "low"

    return {
        "url": url,
        "prediction": (
            "phishing" if is_phishing else "legitimate"
        ),
        "is_phishing": bool(is_phishing),
        "phishing_score": round(phishing_score, 4),
        "score_percentage": round(phishing_score * 100, 2),
        "decision_threshold": round(threshold, 4),
        "risk_level": risk_level,
        "model_name": config["model_name"],
        "features_analyzed": len(feature_columns),
        "features": {
            name: features[name]
            for name in feature_columns
        },
    }
