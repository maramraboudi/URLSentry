from src.data import database
from src.intelligence import urlhaus


class FakeResponse:

    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


def setup_test_database(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "intel_test.db",
    )


def test_missing_api_key(monkeypatch):
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)

    result = urlhaus.lookup_urlhaus(
        "https://example.com"
    )

    assert result["status"] == "unavailable"
    assert result["reason"] == "api_key_not_configured"


def test_url_not_found(tmp_path, monkeypatch):
    setup_test_database(tmp_path, monkeypatch)
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "test-key")

    monkeypatch.setattr(
        urlhaus.requests,
        "post",
        lambda *args, **kwargs: FakeResponse({
            "query_status": "no_results"
        }),
    )

    result = urlhaus.lookup_urlhaus(
        "https://example.com"
    )

    assert result["status"] == "not_found"
    assert result["matched"] is False


def test_url_listed(tmp_path, monkeypatch):
    setup_test_database(tmp_path, monkeypatch)
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "test-key")

    monkeypatch.setattr(
        urlhaus.requests,
        "post",
        lambda *args, **kwargs: FakeResponse({
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "date_added": "2026-01-01 12:00:00",
            "reporter": "test",
            "tags": ["test-tag"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/",
        }),
    )

    result = urlhaus.lookup_urlhaus(
        "https://malicious-example.test/file"
    )

    assert result["status"] == "listed"
    assert result["matched"] is True
    assert result["threat"] == "malware_download"


def test_successful_result_is_cached(tmp_path, monkeypatch):
    setup_test_database(tmp_path, monkeypatch)
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "test-key")

    calls = {"count": 0}

    def fake_post(*args, **kwargs):
        calls["count"] += 1

        return FakeResponse({
            "query_status": "no_results"
        })

    monkeypatch.setattr(
        urlhaus.requests,
        "post",
        fake_post,
    )

    first_result = urlhaus.lookup_urlhaus(
        "https://example.com"
    )

    second_result = urlhaus.lookup_urlhaus(
        "https://example.com"
    )

    assert first_result["status"] == "not_found"
    assert first_result["cache_hit"] is False
    assert second_result["status"] == "not_found"
    assert second_result["cache_hit"] is True
    assert calls["count"] == 1
