import os
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "ml_model", "email_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "ml_model", "email_vectorizer.pkl")

# Cached instances
_model = None
_vectorizer = None


def get_model_and_vectorizer():
    global _model, _vectorizer
    if _model is None or _vectorizer is None:
        _model = joblib.load(MODEL_PATH)
        if not hasattr(_model, "multi_class"):
            _model.multi_class = "auto"
        _vectorizer = joblib.load(VECTORIZER_PATH)
    return _model, _vectorizer


def predict_email(email_text):
    model, vectorizer = get_model_and_vectorizer()
    
    vector = vectorizer.transform([email_text])
    prediction = model.predict(vector)[0]
    probabilities = model.predict_proba(vector)[0]
    confidence = max(probabilities)

    return prediction, confidence