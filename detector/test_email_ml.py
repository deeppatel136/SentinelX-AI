
import os
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model_path = os.path.join(
    BASE_DIR,
    'ml_model',
    'email_model.pkl'
)

vectorizer_path = os.path.join(
    BASE_DIR,
    'ml_model',
    'email_vectorizer.pkl'
)

model = joblib.load(model_path)

vectorizer = joblib.load(vectorizer_path)

email_text = """
Subject: Your account has been suspended.

Verify immediately and update your password.

Click here now.
"""

email_vector = vectorizer.transform(
    [email_text]
)

prediction = model.predict(
    email_vector
)[0]

confidence = max(
    model.predict_proba(
        email_vector
    )[0]
)

print()

if prediction == 1:

    print(
        "Prediction: Phishing"
    )

else:

    print(
        "Prediction: Legitimate"
    )

print(
    f"Confidence: {confidence * 100:.2f}%"
)

print()
