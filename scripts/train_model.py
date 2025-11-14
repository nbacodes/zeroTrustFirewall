"""
train_model.py
---------------
Train a simple RandomForest model to classify phishing URLs.
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
from app.url_inspector import extract_features

def prepare_dataset(phishing_file, benign_file):
    df_phish = pd.read_csv(phishing_file, names=["url"])
    df_phish["label"] = 1  # phishing
    df_benign = pd.read_csv(benign_file, names=["url"])
    df_benign["label"] = 0  # safe
    df = pd.concat([df_phish, df_benign], ignore_index=True)
    return df.sample(frac=1).reset_index(drop=True)  # shuffle

def build_features(df):
    X, y = [], []
    for url, label in zip(df["url"], df["label"]):
        f = extract_features(url)
        X.append([
            f["length"], f["host_len"], f["num_dots"], f["num_slashes"],
            f["entropy"], int(f["contains_at"]), int(f["contains_percent"]),
            int(f["suspicious_tld"])
        ])
        y.append(label)
    return X, y

def main():
    df = prepare_dataset("data/phishing_urls.csv", "data/benign_urls.csv")
    X, y = build_features(df)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=150, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("✅ Model Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    joblib.dump(model, "models/url_clf.joblib")
    print("💾 Model saved to models/url_clf.joblib")

if __name__ == "__main__":
    main()

