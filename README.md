# 🛡️ SentinelX AI

## AI-Powered Multi-Channel Scam & Phishing Detection Platform

SentinelX AI is an AI-powered cybersecurity platform designed to detect, analyze, and explain phishing and scam threats across multiple digital channels.

It combines rule-based security analysis, machine learning, OCR, QR-code analysis, document validation, and AI-powered explanations into a single platform.

> **Detect • Analyze • Protect**

---

## 🚀 Project Overview

Modern phishing attacks are not limited to suspicious URLs.

Attackers can distribute malicious content through:

- 🌐 Websites and URLs
- 📧 Emails
- 🖼️ Images
- 📄 Documents
- 📱 QR codes
- 💳 Payment QR codes
- 📶 WiFi QR codes

SentinelX AI provides a unified security platform for analyzing these different threat sources.

---

# ✨ Features

## 🌐 URL Scanner

Analyzes URLs using security rules and machine learning.

The scanner checks indicators such as:

- URL length
- HTTPS usage
- Suspicious keywords
- Special characters
- URL structure
- Domain/path characteristics
- Suspicious patterns

The URL is then analyzed by the machine-learning model to predict:

- Phishing
- Legitimate

---

## 📧 Email Scanner

Analyzes email content for phishing and scam indicators.

The system checks for:

- Suspicious language
- Urgency indicators
- Sensitive requests
- Suspicious links
- Social-engineering patterns

The final result combines rule-based analysis, ML prediction, and AI-generated explanation.

---

## 🖼️ Image Scanner

SentinelX AI can analyze images containing text.

### Technology

- EasyOCR
- Pillow
- Rule-based analysis
- Machine learning
- AI security explanation

The OCR engine extracts text from the image and sends the extracted content through the security analysis pipeline.

---

# 📄 File Scanner

SentinelX AI supports file-based security analysis.

Supported formats include:

- PDF
- DOCX
- TXT
- JPG
- JPEG
- PNG
- BMP
- WEBP

Before analysis, uploaded files are validated.

### File Validation

The system checks:

- File existence
- File size
- File extension
- File readability
- PDF validity
- Document validity
- Image validity
- Corrupted files

---

# 🔐 Password-Protected PDF Scanner

SentinelX AI supports encrypted/password-protected PDF files.

The workflow is:

```text
Upload PDF
     ↓
Detect Password Protection
     ↓
Ask for Password
     ↓
Authenticate PDF
     ↓
Extract Text
     ↓
Security Analysis
     ↓
Risk Result