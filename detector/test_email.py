
from email_detector import analyze_email

email_text = """

Dear Customer,

Your account has been suspended.

Verify immediately:

http://fake-bank-login.xyz

Regards

Support Team

"""

score, status, reasons = analyze_email(
    email_text
)

print(score)

print(status)

print(reasons)
