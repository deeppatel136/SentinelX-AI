import os
import joblib
import pandas as pd


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml_model",
    "phishing_model.pkl"
)

model = joblib.load(MODEL_PATH)


FEATURE_COLUMNS = [

    "url_length",

    "valid_url",

    "at_symbol",

    "sensitive_words_count",

    "path_length",

    "isHttps",

    "nb_dots",

    "nb_hyphens",

    "nb_and",

    "nb_or",

    "nb_www",

    "nb_com",

    "nb_underscore"

]


def predict_url(features):

    data = pd.DataFrame(
        [features],
        columns=FEATURE_COLUMNS
    )

    prediction = model.predict(data)[0]

    probability = model.predict_proba(data)[0].max()

    return prediction, probability