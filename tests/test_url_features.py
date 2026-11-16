from src.features.url_features import (
    calculate_entropy,
    extract_url_features,
    is_ip_address,
)


def test_https_detection():
    features = extract_url_features("https://example.com")

    assert features["has_https"] == 1


def test_http_detection():
    features = extract_url_features("http://example.com")

    assert features["has_https"] == 0


def test_ip_address_detection():
    features = extract_url_features(
        "https://192.168.1.10/login"
    )

    assert features["has_ip_address"] == 1


def test_suspicious_keyword_detection():
    features = extract_url_features(
        "https://example.com/login/verify"
    )

    assert features["suspicious_keyword_count"] >= 2


def test_query_detection():
    features = extract_url_features(
        "https://example.com/login?user=test"
    )

    assert features["has_query"] == 1
    assert features["question_mark_count"] == 1


def test_digit_features():
    features = extract_url_features(
        "https://example123.com"
    )

    assert features["digit_count"] == 3
    assert features["digit_ratio"] > 0


def test_entropy():
    assert calculate_entropy("") == 0
    assert calculate_entropy("aaaa") == 0
    assert calculate_entropy("abcd") > 0


def test_ip_address_helper():
    assert is_ip_address("192.168.1.1") == 1
    assert is_ip_address("example.com") == 0


def test_feature_values_are_numeric():
    features = extract_url_features(
        "https://example.com/account"
    )

    for value in features.values():
        assert isinstance(value, (int, float))


def test_feature_count():
    features = extract_url_features(
        "https://example.com"
    )

    assert len(features) == 30
