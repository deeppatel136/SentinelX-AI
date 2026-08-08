class QRUtils:

    @staticmethod
    def detect_qr_type(data: str):

        if not data:
            return "Unknown"

        data = data.strip()

        lower_data = data.lower()
        upper_data = data.upper()

        # =====================================
        # UPI Payment
        # =====================================

        if lower_data.startswith("upi://"):
            return "UPI Payment"

        # =====================================
        # WiFi
        # =====================================

        elif upper_data.startswith("WIFI:"):
            return "WiFi Configuration"

        # =====================================
        # Email
        # =====================================

        elif lower_data.startswith("mailto:"):
            return "Email Address"

        # =====================================
        # Phone Number
        # =====================================

        elif lower_data.startswith("tel:"):
            return "Phone Number"

        # =====================================
        # SMS
        # =====================================

        elif lower_data.startswith("smsto:"):
            return "SMS"

        # =====================================
        # Location
        # =====================================

        elif lower_data.startswith("geo:"):
            return "Location"

        # =====================================
        # Contact Card
        # =====================================

        elif upper_data.startswith("BEGIN:VCARD") or upper_data.startswith("MECARD:"):
            return "Contact Card"

        # =====================================
        # Calendar Event
        # =====================================

        elif upper_data.startswith("BEGIN:VCALENDAR"):
            return "Calendar Event"

        # =====================================
        # Cryptocurrency
        # =====================================

        elif lower_data.startswith(("bitcoin:", "ethereum:")):
            return "Crypto Wallet"

        # =====================================
        # Aadhaar (Future)
        # =====================================

        elif "uidai" in lower_data:
            return "Aadhaar"

        # =====================================
        # Digital Payment Links
        # =====================================

        elif "paytm" in lower_data:
            return "Paytm"

        elif "phonepe" in lower_data:
            return "PhonePe"

        elif "gpay" in lower_data or "googlepay" in lower_data:
            return "Google Pay"

        # =====================================
        # WhatsApp
        # =====================================

        elif "wa.me/" in lower_data or "api.whatsapp.com" in lower_data:
            return "WhatsApp"

        # =====================================
        # Website
        # =====================================

        elif lower_data.startswith(("http://", "https://")):
            return "Website URL"

        # =====================================
        # Plain Text
        # =====================================

        return "Plain Text"