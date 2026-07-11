
import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

csv_path = os.path.join(
    BASE_DIR,
    '..',
    'datasets',
    'emails.csv'
)

print("=" * 50)
print("EMAIL PHISHING MODEL TRAINING")
print("=" * 50)

print("\nLoading Dataset...")

df = pd.read_csv(csv_path)

print("Dataset Loaded Successfully")

print(
    f"Rows: {df.shape[0]}"
)

print(
    f"Columns: {df.shape[1]}"
)

# Features

X = df['text']

# Target

y = df['spam']

# Convert text into vectors

vectorizer = TfidfVectorizer(
    stop_words='english',
    max_features=5000
)

X = vectorizer.fit_transform(X)

# Train Test Split

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Model

model = LogisticRegression(
    max_iter=1000
)

print("\nTraining Model...")

model.fit(
    X_train,
    y_train
)

# Prediction

y_pred = model.predict(
    X_test
)

accuracy = accuracy_score(
    y_test,
    y_pred
)

print("\nAccuracy:")
print(
    f"{accuracy * 100:.2f}%"
)

print("\nClassification Report:\n")

print(
    classification_report(
        y_test,
        y_pred
    )
)

# Save Model

model_path = os.path.join(
    BASE_DIR,
    'email_model.pkl'
)

vectorizer_path = os.path.join(
    BASE_DIR,
    'email_vectorizer.pkl'
)

joblib.dump(
    model,
    model_path
)

joblib.dump(
    vectorizer,
    vectorizer_path
)

print("\nModel Saved Successfully")

print(
    model_path
)

print("\nVectorizer Saved Successfully")

print(
    vectorizer_path
)

print("\nTraining Completed")
