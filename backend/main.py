# main.py
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from routers import analyze

load_dotenv()  # reads .env file

# Load API keys — None if not set, features degrade gracefully
SAFE_BROWSING_KEY = os.getenv("SAFE_BROWSING_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not SAFE_BROWSING_KEY:
    print("WARNING: SAFE_BROWSING_API_KEY not set — URL checking disabled")
if not ABUSEIPDB_KEY:
    print("WARNING: ABUSEIPDB_API_KEY not set — IP reputation disabled")

app = FastAPI(title="Malicious Email Scorer API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

# Pass keys to the router
app.include_router(analyze.router)
app.state.safe_browsing_key = SAFE_BROWSING_KEY
app.state.abuseipdb_key = ABUSEIPDB_KEY


@app.get("/health")
def health():
    return {
        "status": "ok",
        "safe_browsing": SAFE_BROWSING_KEY is not None,
        "abuseipdb": ABUSEIPDB_KEY is not None,
    }