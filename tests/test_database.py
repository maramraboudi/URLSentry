from src.data import database


def test_database_initialization(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "test.db",
    )

    database.initialize_database()

    assert database.DATABASE_PATH.exists()


def test_save_and_retrieve_analysis(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "test.db",
    )

    result = {
        "url": "https://example.com",
        "prediction": "legitimate",
        "is_phishing": False,
        "phishing_score": 0.12,
        "risk_level": "low",
        "model_name": "best_model",
        "features_analyzed": 30,
    }

    saved = database.save_analysis(result)

    assert saved["id"] == 1
    assert saved["url"] == result["url"]
    assert saved["prediction"] == "legitimate"

    retrieved = database.get_analysis(saved["id"])

    assert retrieved is not None
    assert retrieved["url"] == result["url"]


def test_history_filtering(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "test.db",
    )

    records = [
        {
            "url": "https://example.com",
            "prediction": "legitimate",
            "is_phishing": False,
            "phishing_score": 0.10,
            "risk_level": "low",
            "model_name": "best_model",
            "features_analyzed": 30,
        },
        {
            "url": "http://suspicious-example.test/login",
            "prediction": "phishing",
            "is_phishing": True,
            "phishing_score": 0.95,
            "risk_level": "high",
            "model_name": "best_model",
            "features_analyzed": 30,
        },
    ]

    for record in records:
        database.save_analysis(record)

    phishing_records = database.get_history(
        prediction="phishing"
    )

    assert len(phishing_records) == 1
    assert phishing_records[0]["prediction"] == "phishing"


def test_statistics(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "test.db",
    )

    database.save_analysis({
        "url": "https://example.com",
        "prediction": "legitimate",
        "is_phishing": False,
        "phishing_score": 0.10,
        "risk_level": "low",
        "model_name": "best_model",
        "features_analyzed": 30,
    })

    database.save_analysis({
        "url": "http://suspicious-example.test/login",
        "prediction": "phishing",
        "is_phishing": True,
        "phishing_score": 0.90,
        "risk_level": "high",
        "model_name": "best_model",
        "features_analyzed": 30,
    })

    stats = database.get_statistics()

    assert stats["total_analyses"] == 2
    assert stats["phishing_count"] == 1
    assert stats["legitimate_count"] == 1
