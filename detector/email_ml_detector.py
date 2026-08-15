import os
import joblib


# ============================================================
# BASE DIRECTORY
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)


# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml_model",
    "email_model.pkl"
)


# ============================================================
# VECTORIZER PATH
# ============================================================

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "ml_model",
    "email_vectorizer.pkl"
)


# ============================================================
# LOAD MODEL
# ============================================================

model = joblib.load(
    MODEL_PATH
)


# ============================================================
# COMPATIBILITY FIX
# ============================================================

# Older versions of scikit-learn stored the
# 'multi_class' attribute inside LogisticRegression.
#
# If the saved model does not contain it,
# restore the expected value before predict_proba().

if not hasattr(
    model,
    "multi_class"
):

    model.multi_class = "auto"


# ============================================================
# LOAD VECTORIZER
# ============================================================

vectorizer = joblib.load(
    VECTORIZER_PATH
)


# ============================================================
# EMAIL PREDICTION
# ============================================================

def predict_email(email_text):

    # --------------------------------------------------------
    # Convert email text into feature vector
    # --------------------------------------------------------

    vector = vectorizer.transform(
        [email_text]
    )


    # --------------------------------------------------------
    # Machine Learning Prediction
    # --------------------------------------------------------

    prediction = model.predict(
        vector
    )[0]


    # --------------------------------------------------------
    # Prediction Confidence
    # --------------------------------------------------------

    probabilities = model.predict_proba(
        vector
    )[0]

    confidence = max(
        probabilities
    )


    # --------------------------------------------------------
    # Return Result
    # --------------------------------------------------------

    return prediction, confidence