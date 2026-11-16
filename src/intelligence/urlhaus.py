
import os
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

from src.data.database import (
    get_cached_intel,
    save_intel_cache,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

load_dotenv(PROJECT_ROOT / ".env")


def unavailable_result(reason, message):
    """Build a consistent result when an intelligence lookup fails."""
    return {
        "provider": "URLhaus",
        "scope": "malware_distribution",
        "status": "unavailable",
        "matched": None,
        "reason": reason,
        "message": message,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "cache_hit": False,
    }


def lookup_urlhaus(url):
    """
    Look up an exact URL in URLhaus.

    This function does not visit the submitted website.
    It sends the URL to URLhaus only when this function is called.
    """
    auth_key = os.getenv("URLHAUS_AUTH_KEY")

    if not auth_key:
        return unavailable_result(
            "api_key_not_configured",
            "URLhaus API key is not configured.",
        )

    cached_result = get_cached_intel(url)

    if cached_result is not None:
        cached_result["cache_hit"] = True
        return cached_result

    headers = {
        "Auth-Key": auth_key,
    }

    try:
        response = requests.post(
            URLHAUS_API_URL,
            data={"url": url},
            headers=headers,
            timeout=(3, 12),
        )
        response.raise_for_status()
        data = response.json()

    except requests.Timeout:
        return unavailable_result(
            "timeout",
            "URLhaus did not respond within the allowed time.",
        )

    except requests.RequestException:
        return unavailable_result(
            "connection_error",
            "Could not communicate with URLhaus.",
        )

    except ValueError:
        return unavailable_result(
            "invalid_response",
            "URLhaus returned an invalid JSON response.",
        )

    if not isinstance(data, dict):
        return unavailable_result(
            "invalid_response",
            "URLhaus returned an unexpected response format.",
        )

    query_status = data.get("query_status")

    if query_status == "no_results":
        result = {
            "provider": "URLhaus",
            "scope": "malware_distribution",
            "status": "not_found",
            "matched": False,
            "message": (
                "No matching URL record was found in URLhaus. "
                "This does not establish that the URL is safe."
            ),
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "cache_hit": False,
        }

        save_intel_cache(url, result)
        return result

    if query_status != "ok":
        return unavailable_result(
            "provider_query_error",
            "URLhaus could not complete the lookup.",
        )

    result = {
        "provider": "URLhaus",
        "scope": "malware_distribution",
        "status": "listed",
        "matched": True,
        "url_status": data.get("url_status"),
        "threat": data.get("threat"),
        "date_added": data.get("date_added"),
        "reporter": data.get("reporter"),
        "tags": data.get("tags", []),
        "reference": data.get("urlhaus_reference"),
        "message": "The exact URL has a matching URLhaus record.",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "cache_hit": False,
    }

    save_intel_cache(url, result)
    return result

