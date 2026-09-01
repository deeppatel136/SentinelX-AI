from .threat_scoring import (
    calculate_threat_score,
    get_severity
)


def analyze_threat(
    scan_type,
    rule_score,
    status,
    reasons=None,
    ml_prediction=None,
    ml_confidence=0
):
    """
    SentinelX Central Threat Analysis Engine.

    Standardizes the output of all scanners.
    """

    if reasons is None:
        reasons = []

    # Normalize ML confidence
    try:
        ml_confidence = float(
            ml_confidence or 0
        )
    except (TypeError, ValueError):
        ml_confidence = 0

    # Calculate unified score
    unified_score = calculate_threat_score(
        rule_score=rule_score,
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence
    )

    severity = get_severity(
        unified_score
    )

    # Final verdict
    if unified_score >= 80:

        verdict = "Dangerous"

    elif unified_score >= 60:

        verdict = "Dangerous"

    elif unified_score >= 30:

        verdict = "Suspicious"

    else:

        verdict = "Safe"

    # Threat indicators
    indicators = []

    for reason in reasons:

        if reason:
            indicators.append(
                str(reason)
            )

    return {

        "scan_type": scan_type,

        "risk_score": unified_score,

        "severity": severity,

        "verdict": verdict,

        "rule_status": status,

        "ml_prediction": ml_prediction,

        "ml_confidence": round(
            ml_confidence,
            2
        ),

        "indicators": indicators,

        "indicator_count": len(
            indicators
        )

    }