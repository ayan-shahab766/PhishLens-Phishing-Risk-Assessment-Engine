"""Train and document the PhishLens baseline text classifier."""

from __future__ import annotations

import json
import pickle
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split


ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "data" / "emails.csv"
BACKEND_PATH = ROOT / "backend"


def main() -> None:
    dataset = pd.read_csv(DATASET_PATH, usecols=["Email Text", "Email Type"])
    dataset = dataset.dropna(subset=["Email Type"])
    dataset["Email Text"] = dataset["Email Text"].fillna("").astype(str)
    labels = dataset["Email Type"].map({"Safe Email": 0, "Phishing Email": 1})
    valid = labels.notna()
    dataset, labels = dataset.loc[valid], labels.loc[valid].astype(int)

    vectorizer = TfidfVectorizer(stop_words="english", max_features=5_000, ngram_range=(1, 2), sublinear_tf=True)
    features = vectorizer.fit_transform(dataset["Email Text"])
    x_train, x_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.25, random_state=42, stratify=labels
    )

    model = GradientBoostingClassifier(random_state=42)
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    probabilities = model.predict_proba(x_test)[:, 1]
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, predictions, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, probabilities)), 4),
    }
    print(json.dumps(metrics, indent=2))
    print(classification_report(y_test, predictions, target_names=["Safe Email", "Phishing Email"], zero_division=0))

    with (BACKEND_PATH / "model.pkl").open("wb") as model_file:
        pickle.dump(model, model_file)
    with (BACKEND_PATH / "vectorizer.pkl").open("wb") as vectorizer_file:
        pickle.dump(vectorizer, vectorizer_file)
    (BACKEND_PATH / "model_metadata.json").write_text(json.dumps({
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_rows": int(len(dataset)),
        "features": int(len(vectorizer.get_feature_names_out())),
        "split": "stratified 75/25, random_state=42",
        "metrics": metrics,
    }, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
