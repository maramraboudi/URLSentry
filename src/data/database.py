
import hashlib
import json
import sqlite3

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATABASE_PATH = PROJECT_ROOT / "data" / "urlsentry.db"


@contextmanager
def get_connection():
    """Open a SQLite connection and always close it safely."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database():
    """Create the application tables and indexes if they do not exist."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL
                    CHECK(prediction IN ('phishing', 'legitimate')),
                is_phishing INTEGER NOT NULL
                    CHECK(is_phishing IN (0, 1)),
                phishing_score REAL NOT NULL
                    CHECK(phishing_score >= 0 AND phishing_score <= 1),
                risk_level TEXT NOT NULL
                    CHECK(risk_level IN ('low', 'elevated', 'high')),
                model_name TEXT NOT NULL,
                features_analyzed INTEGER NOT NULL,
                analyzed_at TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_analyses_timestamp
            ON analyses(analyzed_at)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_analyses_prediction
            ON analyses(prediction)
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_intel_cache (
                url_hash TEXT PRIMARY KEY,
                result_json TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )


def save_analysis(result):
    """Save one ML prediction and return the stored record."""
    initialize_database()

    analyzed_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO analyses (
                url,
                prediction,
                is_phishing,
                phishing_score,
                risk_level,
                model_name,
                features_analyzed,
                analyzed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["url"],
                result["prediction"],
                int(result["is_phishing"]),
                float(result["phishing_score"]),
                result["risk_level"],
                result["model_name"],
                int(result["features_analyzed"]),
                analyzed_at,
            ),
        )

        analysis_id = cursor.lastrowid

        row = connection.execute(
            "SELECT * FROM analyses WHERE id = ?",
            (analysis_id,),
        ).fetchone()

        return dict(row)


def get_analysis(analysis_id):
    """Retrieve one analysis by its database ID."""
    initialize_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM analyses
            WHERE id = ?
            """,
            (analysis_id,),
        ).fetchone()

        return dict(row) if row else None


def get_history(
    limit=50,
    offset=0,
    prediction=None,
    risk_level=None,
):
    """Retrieve analysis history with optional filters."""
    initialize_database()

    query = "SELECT * FROM analyses WHERE 1=1"
    parameters = []

    if prediction:
        query += " AND prediction = ?"
        parameters.append(prediction)

    if risk_level:
        query += " AND risk_level = ?"
        parameters.append(risk_level)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    parameters.extend([limit, offset])

    with get_connection() as connection:
        rows = connection.execute(
            query,
            parameters,
        ).fetchall()

        return [dict(row) for row in rows]


def get_statistics():
    """Return summary statistics for saved analyses."""
    initialize_database()

    with get_connection() as connection:
        summary = connection.execute(
            """
            SELECT
                COUNT(*) AS total_analyses,
                COALESCE(SUM(is_phishing), 0) AS phishing_count,
                COUNT(*) - COALESCE(SUM(is_phishing), 0)
                    AS legitimate_count,
                COALESCE(AVG(phishing_score), 0)
                    AS average_phishing_score
            FROM analyses
            """
        ).fetchone()

        risk_rows = connection.execute(
            """
            SELECT risk_level, COUNT(*) AS count
            FROM analyses
            GROUP BY risk_level
            """
        ).fetchall()

        prediction_rows = connection.execute(
            """
            SELECT prediction, COUNT(*) AS count
            FROM analyses
            GROUP BY prediction
            """
        ).fetchall()

        recent_rows = connection.execute(
            """
            SELECT
                date(analyzed_at) AS analysis_date,
                COUNT(*) AS count
            FROM analyses
            GROUP BY date(analyzed_at)
            ORDER BY analysis_date DESC
            LIMIT 7
            """
        ).fetchall()

        return {
            "total_analyses": summary["total_analyses"],
            "phishing_count": summary["phishing_count"],
            "legitimate_count": summary["legitimate_count"],
            "average_phishing_score": round(
                summary["average_phishing_score"],
                4,
            ),
            "risk_distribution": {
                row["risk_level"]: row["count"]
                for row in risk_rows
            },
            "prediction_distribution": {
                row["prediction"]: row["count"]
                for row in prediction_rows
            },
            "daily_activity": [
                dict(row) for row in reversed(recent_rows)
            ],
        }


def _hash_url(url):
    """Return a SHA-256 hash for a URL cache key."""
    return hashlib.sha256(
        url.encode("utf-8")
    ).hexdigest()


def get_cached_intel(url):
    """Return an unexpired cached intelligence result, if available."""
    initialize_database()

    url_hash = _hash_url(url)

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT result_json, expires_at
            FROM threat_intel_cache
            WHERE url_hash = ?
            """,
            (url_hash,),
        ).fetchone()

        if row is None:
            return None

        expires_at = datetime.fromisoformat(row["expires_at"])

        if datetime.now(timezone.utc) >= expires_at:
            connection.execute(
                """
                DELETE FROM threat_intel_cache
                WHERE url_hash = ?
                """,
                (url_hash,),
            )
            return None

        return json.loads(row["result_json"])


def save_intel_cache(url, result, ttl_hours=6):
    """Store a URLhaus result with a configurable expiration time."""
    if ttl_hours <= 0:
        raise ValueError("Cache lifetime must be greater than zero.")

    initialize_database()

    url_hash = _hash_url(url)
    checked_at = datetime.now(timezone.utc)
    expires_at = checked_at + timedelta(hours=ttl_hours)

    result_to_store = {
        **result,
        "cache_hit": False,
    }

    with get_connection() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO threat_intel_cache (
                url_hash,
                result_json,
                checked_at,
                expires_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                url_hash,
                json.dumps(result_to_store),
                checked_at.isoformat(),
                expires_at.isoformat(),
            ),
        )

