import os

from dotenv import load_dotenv

from google import genai


# ==========================================
# Load Environment Variables
# ==========================================

load_dotenv()

API_KEY = os.getenv(
    "GEMINI_API_KEY"
)

client = genai.Client(
    api_key=API_KEY
)


# ==========================================
# SentinelX AI Chatbot
# ==========================================

def generate_chatbot_response(user_message):

    prompt = f"""
You are SentinelX AI Chatbot.

You are an expert Cybersecurity Assistant.

Your job is to answer ONLY cybersecurity related questions.

Topics include:

• Phishing
• Scam Detection
• Malware
• Ransomware
• Password Security
• Cyber Attacks
• Social Engineering
• Email Security
• URL Safety
• QR Code Fraud
• Banking Fraud
• OTP Fraud
• Privacy
• Digital Safety
• Antivirus
• Firewalls
• VPN
• Cyber Awareness

Rules:

1. Reply in simple English.

2. Use headings whenever appropriate.

3. Give practical cybersecurity advice.

4. Never invent facts.

5. Never create fake statistics.

6. If the question is NOT related to cybersecurity,
politely say:

"I'm SentinelX AI and I specialize in Cybersecurity.
Please ask me anything related to online safety,
phishing, scams, malware, passwords or digital security."

User Question:

{user_message}

"""

    try:

        response = client.models.generate_content(

            model="gemini-2.5-flash",

            contents=prompt

        )

        return response.text

    except Exception as e:

        return f"""
SentinelX AI Chatbot is currently unavailable.

Error:

{str(e)}

Please try again in a few moments.
"""