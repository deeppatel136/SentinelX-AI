class ThreatResult:
    """
    Unified result structure for all SentinelX scanners.

    URL, Email, QR, Image and File scanners can eventually
    use this common structure.
    """

    def __init__(
        self,
        scan_type,
        target=None,
        risk_score=0,
        status="Safe",
        ml_prediction=None,
        ml_confidence=0,
        indicators=None,
        severity=None,
        verdict=None,
        reason=None,
    ):
        self.scan_type = scan_type
        self.target = target
        self.risk_score = float(risk_score)
        self.status = status

        self.ml_prediction = ml_prediction
        self.ml_confidence = float(ml_confidence or 0)

        self.indicators = indicators or []

        self.severity = severity
        self.verdict = verdict
        self.reason = reason

    def calculate_severity(self):
        """
        Convert the numerical risk score into a severity level.
        """

        if self.risk_score >= 80:
            return "CRITICAL"

        if self.risk_score >= 60:
            return "HIGH"

        if self.risk_score >= 40:
            return "MEDIUM"

        if self.risk_score >= 20:
            return "LOW"

        return "INFO"

    def finalize(self):
        """
        Finalize the threat result before returning it.
        """

        self.severity = self.calculate_severity()

        return self

    def to_dict(self):
        """
        Convert the unified result into a dictionary.

        This can later be used by:
        - Django templates
        - JSON APIs
        - PDF reports
        - Dashboard
        - Investigation mode
        - AI analyst
        """

        return {
            "scan_type": self.scan_type,
            "target": self.target,
            "risk_score": round(self.risk_score, 2),
            "status": self.status,

            "ml_prediction": self.ml_prediction,
            "ml_confidence": round(self.ml_confidence, 2),

            "indicators": self.indicators,

            "severity": self.severity,
            "verdict": self.verdict,
            "reason": self.reason,
        }