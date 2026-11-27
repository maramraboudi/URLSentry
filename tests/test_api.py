from fastapi.testclient import TestClient

from app.main import app
from src.data import database


client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["application"] == "URLSentry"


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_prediction_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "api_test.db",
    )

    response = client.post(
        "/predict",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 200

    result = response.json()

    assert result["prediction"] in ["phishing", "legitimate"]
    assert result["features_analyzed"] == 30
    assert len(result["features"]) == 30
    assert result["features"]["hostname_length"] > 0
    assert result["analysis_id"] == 1
    assert "analyzed_at" in result


def test_prediction_rejects_ftp():
    response = client.post(
        "/predict",
        json={"url": "ftp://example.com"},
    )

    assert response.status_code == 400


def test_prediction_rejects_empty_url():
    response = client.post(
        "/predict",
        json={"url": ""},
    )

    assert response.status_code == 422


def test_prediction_rejects_missing_url():
    response = client.post(
        "/predict",
        json={},
    )

    assert response.status_code == 422


def test_history_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "history_test.db",
    )

    client.post(
        "/predict",
        json={"url": "https://example.com"},
    )

    response = client.get("/history")

    assert response.status_code == 200
    assert response.json()["count"] == 1


def test_history_filter(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "filter_test.db",
    )

    # Insert a known legitimate record directly.
    database.save_analysis({
        "url": "https://example.com",
        "prediction": "legitimate",
        "is_phishing": False,
        "phishing_score": 0.10,
        "risk_level": "low",
        "model_name": "best_model",
        "features_analyzed": 30,
    })

    # Request only phishing records.
    response = client.get(
        "/history",
        params={"prediction": "phishing"},
    )

    assert response.status_code == 200
    assert response.json()["count"] == 0
    assert response.json()["results"] == []


def test_statistics_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "stats_test.db",
    )

    client.post(
        "/predict",
        json={"url": "https://example.com"},
    )

    response = client.get("/stats")

    assert response.status_code == 200
    assert response.json()["total_analyses"] == 1


def test_missing_analysis(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "missing_test.db",
    )

    response = client.get("/history/9999")

    assert response.status_code == 404
