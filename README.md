# Malicious Email Scorer

## Project structure

```
email_scorer/
├── backend/
│   ├── main.py            ← FastAPI app entry point
│   ├── models.py          ← Pydantic request/response schemas
│   ├── features.py        ← Feature extraction logic
│   ├── scorer.py          ← Weighted risk scoring engine
│   ├── dataset_logger.py  ← Saves each analysis to dataset.csv
│   ├── requirements.txt
│   └── routers/
│       └── analyze.py     ← POST /analyze endpoint
└── frontend/
    ├── Code.gs            ← Google Apps Script (Gmail Add-on)
    └── appsscript.json    ← Add-on manifest
```

---

## Quick start

### 1 — Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 2 — ngrok tunnel

```bash
ngrok http 8000
# Copy the https URL e.g. https://abc123.ngrok.io
```

### 3 — Update Apps Script

In `Code.gs`, set:
```javascript
var BACKEND_URL = "https://abc123.ngrok.io/analyze";
```

### 4 — Deploy the Add-on

1. Open [script.google.com](https://script.google.com), create a new project.
2. Paste `Code.gs` and `appsscript.json`.
3. Enable the **Gmail API** advanced service.
4. Deploy → New deployment → Gmail Add-on.
5. Open Gmail, open an email, and the side-panel will show the risk score.

---

## API reference

### `POST /analyze`

**Request body** (`EmailPayload`):
```json
{
  "sender_email": "security@paypa1-secure.com",
  "sender_domain": "paypa1-secure.com",
  "reply_to": "harvest@tempmail.org",
  "subject": "URGENT: Verify your account NOW",
  "body_text": "Click immediately to avoid suspension...",
  "links": ["http://bit.ly/abc123"],
  "spf_result": "fail",
  "dkim_result": "fail",
  "dmarc_result": "fail"
}
```

**Response** (`AnalysisResponse`):
```json
{
  "total_score": 85.0,
  "verdict": "phishing",
  "confidence": "high",
  "signals": [
    { "name": "Lookalike domain", "score": 30, "severity": "high", "description": "..." },
    { "name": "Reply-To mismatch", "score": 25, "severity": "high", "description": "..." },
    { "name": "SPF failure", "score": 15, "severity": "medium", "description": "..." }
  ],
  "recommendation": "Do not click any links...",
  "dataset_id": "a3f2b1c0"
}
```

---

## Building your dataset

Every call to `/analyze` appends a row to `dataset.csv`.
After testing, open the CSV and fill in the `label` column:
- `0` = legitimate email
- `1` = phishing / malicious

Once you have ~50+ labelled rows you can train a simple classifier:
```python
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv("dataset.csv").dropna(subset=["label"])
features = ["reply_to_mismatch","spf_fail","dkim_fail","dmarc_fail",
            "suspicious_link_count","urgency_score","num_links",
            "return_path_mismatch","free_email_sender"]

X, y = df[features], df["label"].astype(int)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)
print(model.feature_importances_)
```
