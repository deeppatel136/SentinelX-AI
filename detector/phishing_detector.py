import re
import whois

from datetime import datetime
from urllib.parse import urlparse


def analyze_url(url):

    score = 0
    reasons = []

    suspicious_words = [
        'login',
        'verify',
        'bank',
        'secure',
        'update',
        'account',
        'password',
        'otp'
    ]

    # HTTPS Check

    if not url.startswith("https://"):
        score += 20
        reasons.append("No HTTPS")

    # URL Length Detection

    url_length = len(url)

    if url_length > 100:

        score += 30

        reasons.append(
            "Extremely Long URL"
        )

    elif url_length > 75:

        score += 20

        reasons.append(
            "Very Long URL"
        )

    elif url_length > 50:

        score += 10

        reasons.append(
            "Long URL"
        )

    # IP Address Detection

    ip_pattern = r'\d+\.\d+\.\d+\.\d+'

    if re.search(ip_pattern, url):

        score += 30

        reasons.append(
            "IP Address used instead of domain"
        )

    # URL Shortener Detection

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "is.gd",
        "cutt.ly",
        "shorturl.at"
    ]

    for short in shorteners:

        if short in url.lower():

            score += 25

            reasons.append(
                "URL Shortener Detected"
            )

    # Special Character Detection

    special_chars = [
        '@',
        '%',
        '&',
        '='
    ]

    for ch in special_chars:

        if ch in url:

            score += 15

            reasons.append(
                f"Special Character Found: {ch}"
            )

    # Hyphen Abuse Detection

    if url.count('-') >= 3:

        score += 15

        reasons.append(
            "Too many hyphens in URL"
        )

    # Suspicious Keywords

    for word in suspicious_words:

        if word in url.lower():

            score += 10

            reasons.append(
                f"Suspicious keyword: {word}"
            )

    # Domain Age Check

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
                    datetime.now() -
                    creation_date
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

    # Status

    if score >= 60:

        status = "Dangerous"

    elif score >= 30:

        status = "Suspicious"

    else:

        status = "Safe"

    return score, status, reasons