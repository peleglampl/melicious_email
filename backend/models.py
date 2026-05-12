from pydantic import BaseModel  # pydantic is a library that validates data automatically. BaseModel means "this
# class is a data shape with validation built in."
from typing import Optional


# What is the frontend sent to backend?
class EmailPayload(BaseModel):
    """
    Fields extracted by the Apps Script frontend and sent to the API.
    All fields are optional so the scorer degrades gracefully if
    a header is missing.
    """
    message_id: Optional[str] = None
    sender_email: str
    sender_domain: str
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject: str
    body_text: Optional[str] = None
    links: list[str] = []
    spf_result: Optional[str] = None      # "pass" | "fail" | "softfail" | None
    dkim_result: Optional[str] = None     # "pass" | "fail" | None
    dmarc_result: Optional[str] = None    # "pass" | "fail" | None
    x_mailer: Optional[str] = None
    date_sent: Optional[str] = None
    # Personalization signals — computed client-side for privacy
    prior_contact: Optional[bool] = None
    is_in_contacts: Optional[bool] = None
    domain_thread_count: Optional[int] = None
    is_first_contact_from_domain: Optional[bool] = None
    name_mismatch: Optional[bool] = None



class SignalDetail(BaseModel):
    name: str
    score: float          # contribution to total (0–100 scale, can be negative)
    description: str
    severity: str         # "low" | "medium" | "high" - add a ENUM?


# This is what the backend sends back.  The frontend (Code.gs) reads exactly these fields to build the UI.
# The frontend (Code.gs) reads exactly these fields to build the UI.
class AnalysisResponse(BaseModel):
    total_score: float                  # 0–100
    verdict: str                        # "safe" | "suspicious" | "phishing"
    confidence: str                     # "low" | "medium" | "high"
    signals: list[SignalDetail]
    recommendation: str
    dataset_id: Optional[str] = None   # ID saved to the local dataset
