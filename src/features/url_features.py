import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "confirm",
    "bank",
    "paypal",
    "wallet",
    "billing",
    "invoice",
    "support",
    "recover",
    "authentication",
    "bonus",
    "free",
]


def calculate_entropy(value):
    """Calculate Shannon entropy of a string."""

    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def is_ip_address(hostname):
    """Check whether a hostname is an IPv4 or IPv6 address."""

    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def extract_url_features(url):
    """
    Extract numerical features directly from a URL.

    No website requests or HTML analysis are performed.
    """

    url = str(url).strip()

    # Parse URLs with or without an explicit scheme.
    parsed_input = url

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        parsed_input = "//" + url

    try:
        parsed = urlsplit(parsed_input)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        scheme = parsed.scheme.lower()

        username = parsed.username
        port = parsed.port

    except ValueError:
        hostname = ""
        path = ""
        query = ""
        fragment = ""
        scheme = ""
        username = None
        port = None

    hostname = hostname.lower().rstrip(".")

    url_length = len(url)
    digit_count = sum(character.isdigit() for character in url)
    letter_count = sum(character.isalpha() for character in url)
    special_count = sum(not character.isalnum() for character in url)

    hostname_labels = [
        part for part in hostname.split(".") if part
    ]

    # This is an approximate subdomain count.
    # It does not rely on a public suffix database.
    subdomain_count = max(len(hostname_labels) - 2, 0)

    suspicious_keyword_count = sum(
        len(re.findall(re.escape(keyword), url.lower()))
        for keyword in SUSPICIOUS_KEYWORDS
    )

    features = {
        # URL structure
        "url_length": url_length,
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),

        # Character patterns
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "slash_count": url.count("/"),
        "question_mark_count": url.count("?"),
        "equal_count": url.count("="),
        "at_count": url.count("@"),
        "ampersand_count": url.count("&"),
        "percent_count": url.count("%"),
        "special_character_count": special_count,

        # Numeric and alphabetic patterns
        "digit_count": digit_count,
        "digit_ratio": digit_count / max(url_length, 1),
        "letter_count": letter_count,
        "letter_ratio": letter_count / max(url_length, 1),

        # Domain characteristics
        "has_ip_address": is_ip_address(hostname),
        "subdomain_count": subdomain_count,
        "hostname_label_count": len(hostname_labels),
        "hostname_has_hyphen": int("-" in hostname),
        "has_punycode": int("xn--" in hostname),

        # Security-related indicators
        "has_https": int(scheme == "https"),
        "has_query": int(bool(query)),
        "has_fragment": int(bool(fragment)),
        "has_credentials": int(username is not None),
        "has_port": int(port is not None),
        "suspicious_keyword_count": suspicious_keyword_count,

        # URL complexity
        "url_entropy": calculate_entropy(url),
    }

    return features
