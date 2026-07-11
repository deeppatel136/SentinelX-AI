from feature_extractor import extract_features
from ml_predictor import predict_url

url = "http://bank-login-verify-account.xyz"

features = extract_features(url)

prediction, confidence = predict_url(features)

print("Prediction:", prediction)

print(
    "Confidence:",
    round(confidence * 100, 2),
    "%"
)