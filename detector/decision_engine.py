class DecisionEngine:

    @staticmethod
    def final_verdict(rule_status, ml_status, ml_confidence):

        confidence = float(ml_confidence)

        # --------------------------------------------------
        # CASE 1 : Everything agrees the URL is safe
        # --------------------------------------------------

        if rule_status == "Safe" and ml_status == "Legitimate":

            return {
                "verdict": "SAFE",
                "color": "success",
                "icon": "🟢",
                "reason": (
                    "Both Rule-Based Detection and Machine Learning "
                    "indicate that this QR code appears safe."
                )
            }

        # --------------------------------------------------
        # CASE 2 : Everything agrees it is dangerous
        # --------------------------------------------------

        if rule_status == "Dangerous" and ml_status == "Phishing":

            return {
                "verdict": "DANGEROUS",
                "color": "danger",
                "icon": "🔴",
                "reason": (
                    "Both Rule Engine and Machine Learning "
                    "detected strong phishing indicators."
                )
            }

        # --------------------------------------------------
        # CASE 3 : Rules are Dangerous but ML disagrees
        # --------------------------------------------------

        if rule_status == "Dangerous" and ml_status == "Legitimate":

            return {
                "verdict": "VERIFY MANUALLY",
                "color": "warning",
                "icon": "🟠",
                "reason": (
                    "The Rule Engine detected a high-risk URL, "
                    "while Machine Learning classified it as legitimate."
                )
            }

        # --------------------------------------------------
        # CASE 4 : Rules Suspicious + ML Phishing
        # --------------------------------------------------

        if rule_status == "Suspicious" and ml_status == "Phishing":

            return {
                "verdict": "VERIFY MANUALLY",
                "color": "warning",
                "icon": "🟠",
                "reason": (
                    "Both engines detected suspicious activity, "
                    "but additional manual verification is recommended."
                )
            }

        # --------------------------------------------------
        # CASE 5 : Rules Suspicious + ML Legitimate
        # --------------------------------------------------

        if rule_status == "Suspicious" and ml_status == "Legitimate":

            return {
                "verdict": "SUSPICIOUS",
                "color": "warning",
                "icon": "🟡",
                "reason": (
                    "Rule-Based Detection found suspicious indicators "
                    "although Machine Learning classified it as legitimate."
                )
            }

        # --------------------------------------------------
        # CASE 6 : Rules Safe + ML Phishing
        # --------------------------------------------------

        if rule_status == "Safe" and ml_status == "Phishing":

            if confidence >= 95:

                return {
                    "verdict": "VERIFY MANUALLY",
                    "color": "warning",
                    "icon": "🟠",
                    "reason": (
                        "Machine Learning has very high confidence "
                        "that this URL is phishing, while the Rule Engine "
                        "did not detect significant indicators."
                    )
                }

            return {
                "verdict": "SAFE",
                "color": "success",
                "icon": "🟢",
                "reason": (
                    "Rule-Based Detection considers the QR safe. "
                    "Machine Learning detected weak phishing patterns, "
                    "but confidence is insufficient to classify it as dangerous."
                )
            }

        # --------------------------------------------------
        # Default
        # --------------------------------------------------

        return {
            "verdict": "SAFE",
            "color": "success",
            "icon": "🟢",
            "reason": (
                "No significant phishing indicators were detected."
            )
        }