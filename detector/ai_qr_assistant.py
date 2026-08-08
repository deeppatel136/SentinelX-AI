import os

from google import genai


class AIQRAssistant:

    @staticmethod
    def generate_report(
        qr_type,
        verdict,
        reasons,
        extra_info=""
    ):

        prompt = f"""
You are SentinelX AI,
a professional cybersecurity assistant.

Analyze the following QR scan result.

QR Type:
{qr_type}

Final Verdict:
{verdict}

Threat Indicators:
{chr(10).join(reasons)}

Additional Information:
{extra_info}

Generate a professional cybersecurity report.

The report must include:

1. Executive Summary
2. Risk Explanation
3. Security Recommendations

Maximum 180 words.
"""

        try:

            api_key = os.getenv("GEMINI_API_KEY")

            if not api_key:

                return (
                    "AI Security Assistant is unavailable.\n\n"
                    "Reason: Gemini API key was not found."
                )

            client = genai.Client(api_key=api_key)

            response = client.models.generate_content(

                model="gemini-2.5-flash",

                contents=prompt

            )

            if (
                response
                and hasattr(response, "text")
                and response.text
            ):

                return response.text.strip()

            return (
                "AI Security Assistant could not generate "
                "a response."
            )

        except Exception as e:

            error = str(e).lower()

            # ---------------------------
            # Server Busy
            # ---------------------------

            if "503" in error or "unavailable" in error:

                return (
                    "Google Gemini AI is currently experiencing "
                    "high demand.\n\n"
                    "The QR analysis shown in this report remains "
                    "accurate because it is generated using the "
                    "Rule Engine and Machine Learning."
                )

            # ---------------------------
            # Invalid API Key
            # ---------------------------

            if "api key" in error or "permission" in error:

                return (
                    "Gemini API authentication failed.\n\n"
                    "Please verify the configured API key."
                )

            # ---------------------------
            # Quota Exceeded
            # ---------------------------

            if "quota" in error:

                return (
                    "Gemini API daily quota has been exceeded.\n\n"
                    "Please try again later."
                )

            # ---------------------------
            # Network Error
            # ---------------------------

            return (
                "AI Security Assistant is temporarily unavailable.\n\n"
                "Reason:\n"
                f"{str(e)}"
            )