from urllib.parse import urlparse, parse_qs, unquote


class EmailQRAnalyzer:

    @staticmethod
    def analyze(qr_data):

        result = {

            "email_to": "",

            "subject": "",

            "body": "",

            "email_risk": "Safe",

            "email_reasons": []

        }

        try:

            # mailto:abc@gmail.com?subject=Hello&body=Hi

            parsed = urlparse(qr_data)

            result["email_to"] = parsed.path

            params = parse_qs(parsed.query)

            result["subject"] = unquote(
                params.get("subject", [""])[0]
            )

            result["body"] = unquote(
                params.get("body", [""])[0]
            )

            suspicious_keywords = [

                "verify",

                "otp",

                "bank",

                "password",

                "login",

                "reward",

                "gift",

                "click",

                "urgent",

                "update"

            ]

            content = (

                result["subject"] +

                " " +

                result["body"]

            ).lower()

            for word in suspicious_keywords:

                if word in content:

                    result["email_risk"] = "Suspicious"

                    result["email_reasons"].append(

                        f"Suspicious keyword detected: {word}"

                    )

        except Exception:

            result["email_risk"] = "Unknown"

            result["email_reasons"].append(

                "Unable to analyze Email QR."

            )

        return result