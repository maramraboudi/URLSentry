from fastapi.testclient import TestClient

import app.main as main


client = TestClient(main.app)


def test_intelligence_requires_consent():
    response = client.post(
        "/intelligence/lookup",
        json={
            "url": "https://example.com",
            "share_with_provider": False,
        },
    )

    assert response.status_code == 400


def test_intelligence_lookup_with_consent(monkeypatch):
    def fake_lookup(url):
        return {
            "provider": "URLhaus",
            "scope": "malware_distribution",
            "status": "not_found",
            "matched": False,
            "cache_hit": False,
        }

    monkeypatch.setattr(
        main,
        "lookup_urlhaus",
        fake_lookup,
    )

    response = client.post(
        "/intelligence/lookup",
        json={
            "url": "https://example.com",
            "share_with_provider": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["provider"] == "URLhaus"
    assert response.json()["status"] == "not_found"
