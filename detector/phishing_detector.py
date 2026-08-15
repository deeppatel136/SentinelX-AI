import re
import whois
from datetime import datetime
from urllib.parse import urlparse


def analyze_url(url):
    score = 0
    reasons = []

    # Ensure URL has a scheme for accurate parsing
    if not url.startswith(("http://", "https://")):
        full_url = "http://" + url
    else:
        full_url = url

    parsed_url = urlparse(full_url)
    domain = parsed_url.netloc.split(":")[0]  # Strip port if present
    path_and_query = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")

    suspicious_words = [
        'login', 'verify', 'bank', 'secure',
        'update', 'account', 'password', 'otp'
    ]

    # 1. HTTPS Check
    if not url.startswith("https://"):
        score += 20
        reasons.append("No HTTPS")

    # 2. URL Length Detection
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

    # 3. IP Address Detection
    ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, domain):
        score += 30
        reasons.append("IP Address used instead of domain")

    # 4. URL Shortener Detection
    shorteners = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co",
        "is.gd", "cutt.ly", "shorturl.at"
    ]
    if any(short in domain.lower() for short in shorteners):
        score += 25
        reasons.append("URL Shortener Detected")

    # 5. Suspicious Character Detection (check domain and '@' symbol)
    if '@' in url:
        score += 20
        reasons.append("Contains '@' symbol (often used for credential obfuscation)")

    # 6. Hyphen Abuse in Domain Name
    if domain.count('-') >= 3:
        score += 15
        reasons.append("Too many hyphens in domain name")

    # 7. Suspicious Keywords
    for word in suspicious_words:
        if word in url.lower():
            score += 10
            reasons.append(f"Suspicious keyword: {word}")

    # 8. Domain Age Check via WHOIS
    if domain and not re.match(ip_pattern, domain):
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                if creation_date.tzinfo:
                    creation_date = creation_date.replace(tzinfo=None)

                age_days = (datetime.now() - creation_date).days

                if age_days < 30:
                    score += 30
                    reasons.append(f"Very New Domain ({age_days} days old)")
                elif age_days < 180:
                    score += 15
                    reasons.append(f"New Domain ({age_days} days old)")
        except Exception:
            reasons.append("Domain age could not be verified")

    # Final Classification
    if score >= 60:
        status = "Dangerous"
    elif score >= 30:
        status = "Suspicious"
    else:
        status = "Safe"

    return score, status, reasons