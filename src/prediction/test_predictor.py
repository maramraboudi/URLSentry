from src.prediction.predictor import (
    load_artifacts,
    predict_url,
    validate_url,
)


def test_artifacts_load():
    model, config = load_artifacts()

    assert model is not None
    assert config["features"]
    assert 0 <= config["threshold"] <= 1


def test_valid_https_url():
    result = predict_url("https://example.com")

    assert result["prediction"] in [
        "phishing",
        "legitimate",
    ]

    assert 0 <= result["phishing_score"] <= 1


def test_valid_http_url():
    result = predict_url("http://example.com/login")

    assert result["url"].startswith("http://")


def test_empty_url_rejected():
    try:
        validate_url("")
    except ValueError:
        return

    raise AssertionError("Empty URL should be rejected.")


def test_invalid_scheme_rejected():
    try:
        validate_url("ftp://example.com")
    except ValueError:
        return

    raise AssertionError("FTP URL should be rejected.")


def test_missing_hostname_rejected():
    try:
        validate_url("https:///login")
    except ValueError:
        return

    raise AssertionError("Missing hostname should be rejected.")
