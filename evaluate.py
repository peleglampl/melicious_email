"""
evaluate.py — Run the phishnet scorer against the Nazario phishing CSV dataset
and print accuracy, precision, recall, F1 + confusion matrix.

Usage:
    python evaluate.py --dataset test/Nazario_5.csv
    python evaluate.py --dataset test/Nazario_5.csv --limit 200
"""

import argparse
import ast
import csv
import re
import sys
from pathlib import Path

# ── make sure the backend package is importable ──────────────────────────────
BACKEND_DIR = Path(__file__).parent / "backend"
if BACKEND_DIR.exists():
    sys.path.insert(0, str(BACKEND_DIR))
else:
    sys.path.insert(0, str(Path(__file__).parent))

from models import EmailPayload
from features import extract_features
from scorer import compute_score, verdict_from_score

csv.field_size_limit(10_000_000)


# ── parser: CSV row → EmailPayload ───────────────────────────────────────────

def row_to_payload(row: dict) -> EmailPayload:
    try:
        sender = row.get("sender", "unknown@unknown.com") or "unknown@unknown.com"
        domain = _extract_domain(sender)
        subject = row.get("subject", "") or ""
        body = row.get("body", "") or ""

        # URLs column is a string representation of a list
        raw_urls = row.get("urls", "[]") or "[]"
        try:
            links = ast.literal_eval(raw_urls)
            if not isinstance(links, list):
                links = []
        except Exception:
            links = re.findall(r'https?://[^\s\'"]+', raw_urls)

        return EmailPayload(
            sender_email=sender,
            sender_domain=domain,
            subject=subject,
            body_text=body[:2000],
            links=links[:20],
        )
    except Exception:
        return None


def _extract_domain(address: str) -> str:
    match = re.search(r"@([\w.\-]+)", address)
    return match.group(1).lower() if match else "unknown.com"


# ── evaluation loop ───────────────────────────────────────────────────────────

def evaluate(dataset_path: Path, limit: int = None):
    results = []  # (true_label, predicted_label, score, verdict)
    errors = 0

    with open(dataset_path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if limit and i >= limit:
                break

            true_label = int(row.get("label", 0))
            payload = row_to_payload(row)

            if payload is None:
                errors += 1
                continue

            try:
                features = extract_features(payload)
                score, signals = compute_score(features)
                verdict, _, _ = verdict_from_score(score, len(signals))
                predicted = 1 if verdict in ("phishing", "suspicious") else 0
                results.append((true_label, predicted, score, verdict))
            except Exception:
                errors += 1

    if not results:
        print("No results — check your dataset path.")
        return

    if errors:
        print(f"(skipped {errors} rows due to errors)\n")

    # ── metrics ───────────────────────────────────────────────────────────────
    true_labels = [r[0] for r in results]
    pred_labels = [r[1] for r in results]

    tp = sum(1 for t, p in zip(true_labels, pred_labels) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(true_labels, pred_labels) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(true_labels, pred_labels) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(true_labels, pred_labels) if t == 1 and p == 0)

    total     = len(results)
    accuracy  = (tp + tn) / total if total else 0
    precision = tp / (tp + fp)    if (tp + fp) else 0
    recall    = tp / (tp + fn)    if (tp + fn) else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    # ── score distributions ───────────────────────────────────────────────────
    legit_scores = [r[2] for r in results if r[0] == 0]
    phish_scores = [r[2] for r in results if r[0] == 1]

    # ── verdict breakdown ─────────────────────────────────────────────────────
    phish_results = [r for r in results if r[0] == 1]
    legit_results = [r for r in results if r[0] == 0]

    def verdict_counts(rows):
        counts = {"safe": 0, "suspicious": 0, "phishing": 0}
        for r in rows:
            counts[r[3]] = counts.get(r[3], 0) + 1
        return counts

    phish_verdicts = verdict_counts(phish_results)
    legit_verdicts = verdict_counts(legit_results)

    # ── print report ──────────────────────────────────────────────────────────
    print("\n" + "=" * 52)
    print("          PHISHNET EVALUATION REPORT")
    print("=" * 52)
    print(f"\nDataset:  {dataset_path.name}")
    print(f"Emails:   {total}  ({len(legit_results)} legit / {len(phish_results)} phishing)")

    print(f"\n── Core Metrics ────────────────────────────────")
    print(f"  Accuracy:   {accuracy:.1%}")
    print(f"  Precision:  {precision:.1%}   (flagged emails that were actually phishing)")
    print(f"  Recall:     {recall:.1%}   (phishing emails we caught)")
    print(f"  F1 Score:   {f1:.1%}")

    print(f"\n── Confusion Matrix ────────────────────────────")
    print(f"                   Predicted")
    print(f"                   Safe    Phishing")
    print(f"  Actual Legit     {tn:<7} {fp:<7}  <- false positives")
    print(f"  Actual Phishing  {fn:<7} {tp:<7}  <- true positives")

    print(f"\n── Score Distribution ──────────────────────────")
    if legit_scores:
        print(f"  Legit    — avg: {sum(legit_scores)/len(legit_scores):.1f}  "
              f"min: {min(legit_scores):.1f}  max: {max(legit_scores):.1f}")
    if phish_scores:
        print(f"  Phishing — avg: {sum(phish_scores)/len(phish_scores):.1f}  "
              f"min: {min(phish_scores):.1f}  max: {max(phish_scores):.1f}")

    print(f"\n── Verdict Breakdown ───────────────────────────")
    print(f"  Phishing emails:")
    for v, count in phish_verdicts.items():
        pct = count / len(phish_results) * 100 if phish_results else 0
        bar = "X" * int(pct / 5)
        print(f"    {v:<12} {count:>4}  ({pct:5.1f}%)  {bar}")
    print(f"  Legit emails:")
    for v, count in legit_verdicts.items():
        pct = count / len(legit_results) * 100 if legit_results else 0
        bar = "X" * int(pct / 5)
        print(f"    {v:<12} {count:>4}  ({pct:5.1f}%)  {bar}")

    print("=" * 52)


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate phishnet scorer on Nazario dataset")
    parser.add_argument("--dataset", required=True, help="Path to Nazario_5.csv")
    parser.add_argument("--limit", type=int, default=None, help="Max rows to process")
    args = parser.parse_args()

    evaluate(Path(args.dataset), args.limit)
