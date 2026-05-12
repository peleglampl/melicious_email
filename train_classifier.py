"""
train_classifier.py — Train a TF-IDF + Logistic Regression classifier
on the Nazario dataset and save it to backend/ml_model.pkl

Usage:
    python train_classifier.py --dataset test/Nazario_5.csv
"""

import argparse
import ast
import csv
import pickle
import sys
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix

csv.field_size_limit(10_000_000)


def load_dataset(path: Path):
    texts, labels = [], []
    with open(path, encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            subject = row.get("subject", "") or ""
            body = row.get("body", "") or ""

            # Skip missing data
            if body.strip().lower() == "missing_data":
                body = ""

            text = (subject + " " + body).strip()
            if not text:
                continue

            labels.append(int(row["label"]))
            texts.append(text)

    print(f"Loaded {len(texts)} emails  "
          f"({labels.count(0)} legit / {labels.count(1)} phishing)")
    return texts, labels


def train(dataset_path: Path, model_output: Path):
    texts, labels = load_dataset(dataset_path)

    # ── Pipeline: TF-IDF → Logistic Regression ───────────────────────────────
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=5000,      # top 5000 words
            ngram_range=(1, 2),     # unigrams + bigrams ("click here", "verify account")
            sublinear_tf=True,      # log-scale term frequency
            min_df=2,               # ignore words that appear only once
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",  # handles class imbalance
            C=1.0,
        )),
    ])

    # ── Cross-validation — honest evaluation ─────────────────────────────────
    print("\nRunning 5-fold cross-validation...")
    cv_scores = cross_val_score(pipeline, texts, labels, cv=5, scoring="f1")
    print(f"  F1 scores per fold: {[round(s, 3) for s in cv_scores]}")
    print(f"  Mean F1: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

    cv_recall = cross_val_score(pipeline, texts, labels, cv=5, scoring="recall")
    print(f"  Mean Recall: {cv_recall.mean():.3f}")

    cv_precision = cross_val_score(pipeline, texts, labels, cv=5, scoring="precision")
    print(f"  Mean Precision: {cv_precision.mean():.3f}")

    # ── Train on full dataset and show test split report ──────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    print("\nTest split report (20% holdout):")
    print(classification_report(y_test, y_pred, target_names=["legit", "phishing"]))

    print("Confusion matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"  FN={cm[1][0]}  TP={cm[1][1]}")

    # ── Top phishing words ────────────────────────────────────────────────────
    feature_names = pipeline.named_steps["tfidf"].get_feature_names_out()
    coefs = pipeline.named_steps["clf"].coef_[0]
    top_phishing = sorted(zip(coefs, feature_names), reverse=True)[:15]
    print("\nTop 15 phishing indicator words/phrases:")
    for coef, word in top_phishing:
        print(f"  {word:<30} {coef:.3f}")

    # ── Retrain on ALL data and save ─────────────────────────────────────────
    print(f"\nRetraining on full dataset and saving to {model_output}...")
    pipeline.fit(texts, labels)

    model_output.parent.mkdir(parents=True, exist_ok=True)
    with open(model_output, "wb") as f:
        pickle.dump(pipeline, f)

    print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output", default="backend/ml_model.pkl")
    args = parser.parse_args()

    train(Path(args.dataset), Path(args.output))
