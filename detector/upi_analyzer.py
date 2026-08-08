from urllib.parse import urlparse, parse_qs, unquote


class UPIAnalyzer:

    @staticmethod
    def analyze(qr_data):

        parsed = urlparse(qr_data)

        params = parse_qs(parsed.query)

        upi_id = unquote(params.get("pa", ["Not Found"])[0])

        receiver = unquote(params.get("pn", ["Unknown"])[0])

        amount = unquote(params.get("am", ["Not Specified"])[0])

        note = unquote(params.get("tn", ["None"])[0])

        bank = "Unknown"

        if "@" in upi_id:
            bank = upi_id.split("@")[1]

        risk = "Safe"

        reasons = []

        suspicious_words = [
            "support",
            "refund",
            "cashback",
            "reward",
            "gift",
            "offer"
        ]

        for word in suspicious_words:

            if word in receiver.lower():

                risk = "Suspicious"

                reasons.append(
                    f"Suspicious receiver keyword: {word}"
                )

        return {

            "receiver": receiver,

            "upi_id": upi_id,

            "bank": bank,

            "amount": amount,

            "note": note,

            "upi_risk": risk,

            "upi_reasons": reasons

        }