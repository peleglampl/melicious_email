import csv
import uuid
from datetime import datetime
from pathlib import Path

DATASET_PATH = Path("dataset.csv")

FIELDNAMES = [
    "id", "timestamp",
    "sender_domain", "reply_to_mismatch", "spf_fail", "dkim_fail", "dmarc_fail",
    "lookalike_domain", "suspicious_link_count", "urgency_score", "num_links",
    "return_path_mismatch", "free_email_sender",
    "total_score", "verdict",
    "label",   # filled in manually later: 0=legit, 1=phishing
]


def log_to_dataset(features: dict, total_score: float, verdict: str) -> str:
    """
    Appends one row to dataset.csv. Returns the row ID.
    The 'label' column is left empty — you fill it manually for ground truth.
    """
    row_id = str(uuid.uuid4())[:8]

    # Create file with header if it doesn't exist
    write_header = not DATASET_PATH.exists()

    with open(DATASET_PATH, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        if write_header:
            writer.writeheader()

        writer.writerow({
            "id": row_id,
            "timestamp": datetime.utcnow().isoformat(),
            "sender_domain": features.get("sender_domain", ""),
            "reply_to_mismatch": int(features.get("reply_to_mismatch", False)),
            "spf_fail": int(features.get("spf_fail", False)),
            "dkim_fail": int(features.get("dkim_fail", False)),
            "dmarc_fail": int(features.get("dmarc_fail", False)),
            "lookalike_domain": features.get("lookalike_domain") or "",
            "suspicious_link_count": features.get("suspicious_link_count", 0),
            "urgency_score": round(features.get("urgency_score", 0.0), 3),
            "num_links": features.get("num_links", 0),
            "return_path_mismatch": int(features.get("return_path_mismatch", False)),
            "free_email_sender": int(features.get("free_email_sender", False)),
            "total_score": total_score,
            "verdict": verdict,
            "label": "",  # fill manually: 0 or 1
        })

    return row_id
