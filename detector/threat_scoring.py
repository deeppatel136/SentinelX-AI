def calculate_threat_score(
    rule_score=0,
    ml_prediction=None,
    ml_confidence=0
):
    """
    SentinelX Threat Scoring Engine

    Combines:
    - Rule-based risk score
    - Machine-learning prediction
    - ML confidence

    Returns a normalized score from 0-100.
    """

    try:
        rule_score = float(rule_score or 0)
    except (TypeError, ValueError):
        rule_score = 0

    try:
        ml_confidence = float(ml_confidence or 0)
    except (TypeError, ValueError):
        ml_confidence = 0

    # Keep values within valid range
    rule_score = max(0, min(rule_score, 100))
    ml_confidence = max(0, min(ml_confidence, 100))

    # Base score from rule engine
    score = rule_score

    # ML contribution
    if ml_prediction == "Phishing":
        score = (rule_score * 0.60) + (ml_confidence * 0.40)

    elif ml_prediction == "Legitimate":
        # Legitimate prediction should reduce, not completely erase,
        # rule-based evidence.
        ml_safety = 100 - ml_confidence
        score = (rule_score * 0.75) + (ml_safety * 0.25)

    score = round(max(0, min(score, 100)), 2)

    return score


def get_severity(score):
    """
    Convert risk score into SentinelX severity.
    """

    score = float(score)

    if score < 30:
        return "SAFE"

    elif score < 60:
        return "SUSPICIOUS"

    elif score < 80:
        return "HIGH"

    return "CRITICAL"