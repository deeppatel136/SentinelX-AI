import os
import joblib

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    'ml_model',
    'email_model.pkl'
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    'ml_model',
    'email_vectorizer.pkl'
)

model = joblib.load(
    MODEL_PATH
)

vectorizer = joblib.load(
    VECTORIZER_PATH
)


def predict_email(email_text):

    vector = vectorizer.transform(
        [email_text]
    )

    prediction = model.predict(
        vector
    )[0]

    confidence = max(
        model.predict_proba(
            vector
        )[0]
    )

    return prediction, confidence
