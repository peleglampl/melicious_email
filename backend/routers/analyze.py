from fastapi import APIRouter, Request
from models import EmailPayload, AnalysisResponse
from features import extract_features
from scorer import compute_score, verdict_from_score
from dataset_logger import log_to_dataset

router = APIRouter()

@router.post("/analyze", response_model=AnalysisResponse)
def analyze_email(payload: EmailPayload, request: Request) -> AnalysisResponse:
    # Get API keys from app state
    safe_browsing_key = request.app.state.safe_browsing_key
    abuseipdb_key = request.app.state.abuseipdb_key

    # 1. Extract features — now with API keys
    features = extract_features(
        payload,
        safe_browsing_key=safe_browsing_key,
        abuseipdb_key=abuseipdb_key
    )
    features["sender_domain"] = payload.sender_domain

    # 2. Score
    total_score, signals = compute_score(features)

    # 3. Verdict
    verdict, confidence, recommendation = verdict_from_score(total_score, len(signals))

    # 4. Save to dataset
    row_id = log_to_dataset(features, total_score, verdict)

    return AnalysisResponse(
        total_score=total_score,
        verdict=verdict,
        confidence=confidence,
        signals=signals,
        recommendation=recommendation,
        dataset_id=row_id,
    )