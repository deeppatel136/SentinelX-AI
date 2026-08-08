import re


class WiFiAnalyzer:

    @staticmethod
    def analyze(qr_data):

        result = {
            "ssid": "Unknown",
            "password": "",
            "encryption": "Unknown",
            "wifi_risk": "Safe",
            "wifi_reasons": []
        }

        try:

            ssid = re.search(r"S:([^;]*)", qr_data)
            password = re.search(r"P:([^;]*)", qr_data)
            encryption = re.search(r"T:([^;]*)", qr_data)

            if ssid:
                result["ssid"] = ssid.group(1)

            if password:
                result["password"] = password.group(1)

            if encryption:
                result["encryption"] = encryption.group(1)

            # -------- Security Checks -------- #

            enc = result["encryption"].upper()

            if enc == "NOPASS":

                result["wifi_risk"] = "Dangerous"

                result["wifi_reasons"].append(
                    "Open WiFi network (No password)"
                )

            elif enc == "WEP":

                result["wifi_risk"] = "Suspicious"

                result["wifi_reasons"].append(
                    "WEP encryption is outdated."
                )

            elif enc in ["WPA", "WPA2", "WPA3"]:

                result["wifi_reasons"].append(
                    f"{enc} encryption detected."
                )

            if len(result["password"]) < 8:

                result["wifi_reasons"].append(
                    "Weak WiFi password."
                )

        except Exception:

            result["wifi_risk"] = "Unknown"

            result["wifi_reasons"].append(
                "Unable to analyze WiFi QR."
            )

        return result