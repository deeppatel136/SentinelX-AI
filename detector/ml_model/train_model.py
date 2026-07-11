import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# ==========================================
# Dataset Path
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

csv_path = os.path.join(
    BASE_DIR,
    '..',
    'datasets',
    'phishing_url_dataset.csv'
)

print("=" * 60)
print("SENTINELX AI - URL PHISHING MODEL TRAINING")
print("=" * 60)

print("\nLoading Dataset...")
print(csv_path)

# ==========================================
# Load Dataset
# ==========================================

df = pd.read_csv(csv_path)

print("\nDataset Loaded Successfully")

print(f"Rows    : {df.shape[0]}")
print(f"Columns : {df.shape[1]}")

# ==========================================
# Feature Order (Must Match feature_extractor.py)
# ==========================================

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

X = df[FEATURE_COLUMNS]

y = df["target"]

print("\nFeature Columns:")
print(FEATURE_COLUMNS)

# ==========================================
# Train Test Split
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(

    X,

    y,

    test_size=0.20,

    random_state=42,

    stratify=y

)

print("\nTraining Records :", len(X_train))
print("Testing Records  :", len(X_test))

# ==========================================
# Random Forest
# ==========================================

model = RandomForestClassifier(

    n_estimators=300,

    max_depth=None,

    min_samples_split=2,

    min_samples_leaf=1,

    random_state=42,

    n_jobs=-1

)

print("\nTraining Model...")

model.fit(
    X_train,
    y_train
)

# ==========================================
# Prediction
# ==========================================

y_pred = model.predict(X_test)

# ==========================================
# Accuracy
# ==========================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

print("\n" + "=" * 60)
print(f"Accuracy : {accuracy * 100:.2f}%")
print("=" * 60)

print("\nClassification Report\n")

print(

    classification_report(

        y_test,

        y_pred

    )

)

print("\nConfusion Matrix\n")

print(

    confusion_matrix(

        y_test,

        y_pred

    )

)

# ==========================================
# Feature Importance
# ==========================================

print("\n" + "=" * 60)
print("FEATURE IMPORTANCE")
print("=" * 60)

importance = pd.DataFrame({

    "Feature": FEATURE_COLUMNS,

    "Importance": model.feature_importances_

})

importance = importance.sort_values(

    by="Importance",

    ascending=False

)

print(importance)

# ==========================================
# Save Model
# ==========================================

model_path = os.path.join(

    BASE_DIR,

    "phishing_model.pkl"

)

joblib.dump(

    model,

    model_path

)

print("\nModel Saved Successfully")

print(model_path)

print("\nTraining Completed Successfully.")