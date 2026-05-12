from __future__ import annotations
import re  # regular expressions
# Levenshtein — a library that measures how "different" two strings are.
from Levenshtein import distance as levenshtein_distance
import requests

from models import EmailPayload  # from models import EmailPayload — importing the data shape we just reviewed

# Domains to check lookalike against
TRUSTED_DOMAINS = [
    "google.com", "gmail.com", "paypal.com", "amazon.com", "apple.com",
    "microsoft.com", "facebook.com", "netflix.com", "instagram.com",
]

# These are regex patterns for urgency language.
URGENCY_PATTERNS = [
    r"urgent", r"immediate(ly)?", r"act now", r"verify.{0,10}account",
    r"suspended", r"limited.{0,10}time", r"click.{0,10}now",
    r"confirm.{0,10}identity", r"unusual.{0,10}activity",
]


THREAT_PATTERNS = {
    "credential_harvesting": [
        r"verify.{0,20}(password|login|account|identity)",
        r"confirm.{0,20}(details|information|credentials)",
        r"(account|access).{0,15}(suspended|locked|compromised)",
    ],
    "financial_fraud": [
    r"(wire|transfer|send).{0,20}(money|funds|payment|bitcoin)",
    r"(invoice|payment).{0,20}(attached|due|overdue|pending)",
    r"(bank|account).{0,20}(details|information|number)",
    r"transaction.{0,20}(completed|processed|successful)",
    r"amount.{0,10}\$[\d,]+",
    r"paypal.{0,20}(transaction|payment|account)",
],
    "malware_delivery": [
        r"(open|download|view|enable).{0,20}(attachment|document|file|macro)",
        r"(invoice|receipt|shipment).{0,10}(attached|enclosed)",
    ],
    "authority_impersonation": [
        r"(ceo|cfo|director|manager).{0,20}(asking|requesting|need)",
        r"(legal|compliance|audit).{0,20}(required|mandatory|immediate)",
        r"do not (discuss|mention|tell)",  # secrecy request — BEC hallmark
    ]
}



def extract_features(payload: EmailPayload,
                     raw_headers: dict = {},
                     safe_browsing_key: str | None = None,
                     abuseipdb_key: str | None = None) -> dict:
    homoglyphs = _unicode_homoglyphs(payload.subject)
    clean_body = _sanitize_text(payload.body_text or "")

    # External checks — only run if API keys are provided
    flagged_urls = []
    if safe_browsing_key and payload.links:
        flagged_urls = check_urls_safe_browsing(payload.links, safe_browsing_key)

    sending_ip = extract_sending_ip(raw_headers)
    bad_ip = False
    if abuseipdb_key and sending_ip:
        bad_ip = check_ip_reputation(sending_ip, abuseipdb_key)

    return {
        "reply_to_mismatch": _reply_to_mismatch(payload),
        "lookalike_domain": _lookalike_domain(payload.sender_domain),
        "spf_fail": _auth_fail(payload.spf_result),
        "dkim_fail": _auth_fail(payload.dkim_result),
        "dmarc_fail": _auth_fail(payload.dmarc_result),
        "suspicious_link_count": _suspicious_links(payload.links),
        "urgency_score": _urgency_score(payload.subject, clean_body),
        "num_links": len(payload.links),
        "return_path_mismatch": _return_path_mismatch(payload),
        "free_email_sender": _is_free_email(payload.sender_domain),
        "unicode_homoglyphs": homoglyphs,
        "display_name_spoof": _display_name_spoof(payload),
        "flagged_urls": flagged_urls,  # list of confirmed malicious URLs
        "bad_sender_ip": bad_ip,  # True if IP is on abuse blacklist
        "random_username": _random_username(payload.sender_email),
        "threat_types": _classify_threat_type(payload.subject, payload.body_text),
        "name_mismatch": payload.name_mismatch or False,
        # In features.py — add to extract_features return dict:
        "secrecy_request": bool(re.search(r"do not (discuss|mention|tell|share)",
                                          (payload.body_text or "").lower())),
    }


# Replay To mismatch:
def _reply_to_mismatch(payload: EmailPayload) -> bool:
    if not payload.reply_to:
        return False
    reply_domain = _extract_domain(payload.reply_to)
    return reply_domain != payload.sender_domain


# Using Levenshtein distance- a package
def _lookalike_domain(domain: str) -> str | None:
    """Return the trusted domain that `domain` most closely resembles, or None."""
    domain = domain.lower().split(":")[0]   # strip port if present
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted:
            return None   # exact match — not a lookalike
        dist = levenshtein_distance(domain, trusted)
        if 1 <= dist <= 3:
            return trusted  # check 1: returns the closest
        # Homoglyph-style check: normalise common substitutions
        normalised = domain.translate(str.maketrans("0134@", "olaaa"))
        if normalised == trusted:
            return trusted
    return None


def _auth_fail(result: str | None) -> bool:
    if result is None:
        return False
    return result.lower() not in ("pass",)


# using re here - giving score of short url, raw IP address, lookalike domain
def _suspicious_links(links: list[str]) -> int:
    suspicious = 0
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "cutt.ly"}
    for link in links:
        domain = _extract_domain(link)
        if domain in shorteners:
            suspicious += 1
        elif re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", link):  # raw IP
            suspicious += 1
        elif domain and _lookalike_domain(domain):
            suspicious += 1
    return suspicious


def _urgency_score(subject: str, body: str | None) -> float:
    text = (subject + " " + (body or "")).lower()
    matches = sum(1 for p in URGENCY_PATTERNS if re.search(p, text))
    return min(matches / len(URGENCY_PATTERNS), 1.0)


def _return_path_mismatch(payload: EmailPayload) -> bool:
    if not payload.return_path:
        return False
    rp_domain = _extract_domain(payload.return_path)
    return rp_domain != payload.sender_domain


# checking if the email is common (free)
def _is_free_email(domain: str) -> bool:
    free = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"}
    return domain.lower() in free


def _extract_domain(address: str) -> str:
    """Extract domain from 'Name <user@domain.com>' or 'user@domain.com'."""
    match = re.search(r"@([\w.\-]+)", address)
    return match.group(1).lower() if match else address.lower()


# Added this:
def _display_name_spoof(payload: EmailPayload) -> bool:
    # Extract display name from "PayPal Support <user@gmail.com>"
    match = re.match(r'^"?([^"<]+)"?\s*<', payload.sender_email)
    if not match:
        return False
    display_name = match.group(1).strip().lower()
    for trusted in TRUSTED_DOMAINS:
        brand = trusted.split(".")[0]  # "paypal", "google", etc.
        if brand in display_name:
            return True
    return False


def _unicode_homoglyphs(text: str) -> list[str]:
    found = []
    for char in text:
        code = ord(char)
        if 0x0400 <= code <= 0x04FF:
            found.append(f"'{char}' (Cyrillic U+{code:04X})")
        elif 0x0370 <= code <= 0x03FF:
            found.append(f"'{char}' (Greek U+{code:04X})")
    return found


# Google Safe Browsing API — The Perfect Privacy Solution
def check_urls_safe_browsing(urls: list[str], api_key: str) -> list[str]:
    """
    Returns list of URLs flagged as malicious by Google Safe Browsing.
    Uses Lookup API for simplicity.
    For full privacy, use Update API with hash prefixes.
    """
    if not urls:
        return []

    payload = {
        "client": {"clientId": "email-scorer", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls]
        }
    }

    resp = requests.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
        json=payload,
        timeout=5
    )

    if resp.status_code != 200:
        return []  # fail-safe — don't penalize if API is down

    matches = resp.json().get("matches", [])
    return [m["threat"]["url"] for m in matches]


def extract_sending_ip(headers: dict) -> str | None:
    """Extract the originating IP from Received headers."""
    received = headers.get("Received", "")
    match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received)
    return match.group(1) if match else None


def check_ip_reputation(ip: str, api_key: str) -> bool:  # ✅ key as parameter
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=5
    )
    if resp.status_code != 200:
        return False
    return resp.json()["data"]["abuseConfidenceScore"] > 50


def _sanitize_text(text: str, max_length: int = 2000) -> str:
    """
    Strips null bytes and control characters, caps length.
    Prevents ReDoS and memory exhaustion from malicious payloads.
    """
    text = text.replace("\x00", "")  # null bytes
    text = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)  # control chars
    return text[:max_length]


def _classify_threat_type(subject: str, body: str | None) -> dict:
    """
    Identifies WHAT TYPE of attack is being attempted.
    More actionable than a generic urgency score.
    """
    text = (subject + " " + (body or "")).lower()
    results = {}
    for threat_type, patterns in THREAT_PATTERNS.items():
        matches = sum(1 for p in patterns if re.search(p, text))
        if matches > 0:
            results[threat_type] = matches
    return results


def _random_username(sender_email: str) -> bool:
    """Flags generated accounts like g97496398@gmail.com"""
    # Handle "Display Name <user@domain.com>" format
    email_match = re.search(r'<([^>]+)>', sender_email)
    actual_email = email_match.group(1) if email_match else sender_email

    match = re.match(r'^([^@]+)@', actual_email)
    if not match:
        return False
    username = match.group(1)
    digit_ratio = sum(c.isdigit() for c in username) / len(username)
    return digit_ratio > 0.5