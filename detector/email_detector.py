
import re


def analyze_email(email_text):

    score = 0

    reasons = []

    suspicious_words = [

        'verify',
        'account',
        'password',
        'bank',
        'login',
        'otp',
        'update',
        'reward',
        'winner',
        'gift'

    ]

    urgent_words = [

        'urgent',
        'immediately',
        'within 24 hours',
        'suspended',
        'blocked'

    ]

    # =====================
    # Suspicious Keywords
    # =====================

    for word in suspicious_words:

        if word in email_text.lower():

            score += 10

            reasons.append(
                f"Suspicious keyword: {word}"
            )

    # =====================
    # Urgent Language
    # =====================

    for word in urgent_words:

        if word in email_text.lower():

            score += 15

            reasons.append(
                f"Urgent language detected: {word}"
            )

    # =====================
    # URL Detection
    # =====================

    urls = re.findall(
        r'https?://\S+',
        email_text
    )

    if urls:

        score += 20

        reasons.append(
            "Contains URL"
        )

    # =====================
    # Final Status
    # =====================

    if score >= 60:

        status = "Dangerous"

    elif score >= 30:

        status = "Suspicious"

    else:

        status = "Safe"

    return score, status, reasons
