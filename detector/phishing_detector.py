import re
import whois

from datetime import datetime
from urllib.parse import urlparse

from .threat_result import ThreatResult


def analyze_url(url):
    """
    Analyze a URL using SentinelX rule-based detection.

    Existing detection logic is preserved.
    The function now returns a unified ThreatResult object.
    """

    score = 0
    reasons = []

    suspicious_words = [
        "login",
        "verify",
        "bank",
        "secure",
        "update",
        "account",
        "password",
        "otp",
    ]

    # --------------------------------------------------
    # HTTPS CHECK
    # --------------------------------------------------

    if not url.startswith("https://"):
        score += 20
        reasons.append("No HTTPS")

    # --------------------------------------------------
    # URL LENGTH DETECTION
    # --------------------------------------------------

    url_length = len(url)

    if url_length > 100:
        score += 30
        reasons.append("Extremely Long URL")

    elif url_length > 75:
        score += 20
        reasons.append("Very Long URL")

    elif url_length > 50:
        score += 10
        reasons.append("Long URL")

    # --------------------------------------------------
    # IP ADDRESS DETECTION
    # --------------------------------------------------

    ip_pattern = r"\d+\.\d+\.\d+\.\d+"

    if re.search(ip_pattern, url):
        score += 30
        reasons.append(
            "IP Address used instead of domain"
        )

    # --------------------------------------------------
    # URL SHORTENER DETECTION
    # --------------------------------------------------

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "is.gd",
        "cutt.ly",
        "shorturl.at",
    ]

    for short in shorteners:

        if short in url.lower():

            score += 25

            reasons.append(
                "URL Shortener Detected"
            )

    # --------------------------------------------------
    # SPECIAL CHARACTER DETECTION
    # --------------------------------------------------

    special_chars = [
        "@",
        "%",
        "&",
        "=",
    ]

    for ch in special_chars:

        if ch in url:

            score += 15

            reasons.append(
                f"Special Character Found: {ch}"
            )

    # --------------------------------------------------
    # HYPHEN ABUSE DETECTION
    # --------------------------------------------------

    if url.count("-") >= 3:

        score += 15

        reasons.append(
            "Too many hyphens in URL"
        )

    # --------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------

    for word in suspicious_words:

        if word in url.lower():

            score += 10

            reasons.append(
                f"Suspicious keyword: {word}"
            )

    # --------------------------------------------------
    # DOMAIN AGE CHECK
    # --------------------------------------------------

    try:

        parsed_url = urlparse(url)

        domain = parsed_url.netloc

        if not re.search(ip_pattern, domain):

            domain_info = whois.whois(domain)

            creation_date = domain_info.creation_date

            if isinstance(creation_date, list):

                creation_date = creation_date[0]

            if creation_date:

                if creation_date.tzinfo:

                    creation_date = creation_date.replace(
                        tzinfo=None
                    )

                age_days = (
                    datetime.now() - creation_date
                ).days

                if age_days < 30:

                    score += 30

                    reasons.append(
                        f"Very New Domain ({age_days} days old)"
                    )

                elif age_days < 180:

                    score += 15

                    reasons.append(
                        f"New Domain ({age_days} days old)"
                    )

    except Exception:

        reasons.append(
            "Domain age could not be verified"
        )

    # --------------------------------------------------
    # STATUS
    # --------------------------------------------------

    if score >= 60:

        status = "Dangerous"

    elif score >= 30:

        status = "Suspicious"

    else:

        status = "Safe"

    # --------------------------------------------------
    # UNIFIED THREAT RESULT
    # --------------------------------------------------

    result = ThreatResult(

        scan_type="URL",

        target=url,

        risk_score=min(score, 100),

        status=status,

        indicators=reasons,

    )

    # Finalize severity
    result.finalize()

    return result