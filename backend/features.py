from __future__ import annotations
import re  # regular expressions
# Levenshtein — a library that measures how "different" two strings are.
from Levenshtein import distance as levenshtein_distance
import requests
from ml_classifier import ml_phishing_score

from models import EmailPayload  # from models import EmailPayload — importing the data shape we just reviewed

# Domains to check lookalike against
TRUSTED_DOMAINS = [
    "google.com", "gmail.com", "paypal.com", "amazon.com", "apple.com",
    "microsoft.com", "facebook.com", "netflix.com", "instagram.com",
]

# These are regex patterns for urgency language.
URGENCY_PATTERNS = [
    # Original patterns
    r"urgent", r"immediate(ly)?", r"act now", r"verify.{0,10}account",
    r"suspended", r"limited.{0,10}time", r"click.{0,10}now",
    r"confirm.{0,10}identity", r"unusual.{0,10}activity",
    # Added from real phishing examples (Nazario corpus)
    r"password.{0,15}(expire|expir)",        # "password will expire in 3 days"
    r"(validate|verify).{0,15}(e.?mail|account|identity)",  # "validate e-mail"
    r"click.{0,15}(here|below|link).{0,15}(to|and)",        # "click here to validate"
    r"account.{0,20}(pending|on hold|suspended|locked|blocked)",
    r"(update|confirm).{0,15}(your|account).{0,15}(info|detail|data)",
    r"(login|log in|sign in).{0,20}(to|and).{0,20}(confirm|verify|validate|re.confirm)",
    r"(mailbox|inbox).{0,20}(full|warning|alert|upgrade)",
    r"(system|server|database).{0,20}(upgrade|maintenance|migration)",
    r"failure.{0,20}(to|will).{0,20}(do|result|affect|suspend)",
    r"dear.{0,10}(client|member|user|customer|valued)",      # impersonal salutation
    r"(exceed|reaching).{0,20}(limit|quota|storage|capacity)",
    r"click.{0,15}(here|below).{0,15}(to|and).{0,15}(renew|reactivate|restore|upgrade)",
    r"(mailbox|account|inbox).{0,20}(almost|nearly|about to).{0,20}(full|exceed|limit)",
    r"(won't|will not|cannot|may not).{0,20}(send|receive).{0,20}(message|email|mail)",
]


THREAT_PATTERNS = {
    "credential_harvesting": [
        r"verify.{0,20}(password|login|account|identity)",
        r"confirm.{0,20}(details|information|credentials)",
        r"(account|access).{0,15}(suspended|locked|compromised)",
        # Added from real phishing examples
        r"(enter|provide|submit).{0,20}(username|password|credentials)",
        r"(userid|user.?id|email).{0,10}(:|=|\s)",              # login form fields
        r"re.?confirm.{0,20}(account|password|email)",
        r"(validate|verify).{0,20}(e.?mail|webmail|mailbox)",
        r"(incorrect|inaccurate|unverified).{0,20}(data|info|detail)",
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
        r"do not (discuss|mention|tell)",                        # BEC hallmark
        # Added from real phishing examples
        r"(help.?desk|it.?support|technical.?support).{0,20}(alert|warning|notice)",
        r"(usaa|paypal|apple|microsoft|amazon).{0,30}(security|account|member)",
        r"security.{0,20}(zone|upgrade|alert|notice|update)",
    ],
    "account_takeover": [
        # New category — covers the most common Nazario pattern
        r"(account|mailbox|inbox).{0,20}(verification|upgrade|migration)",
        r"(expire|expir).{0,20}(password|account|access)",
        r"(pending|on.hold).{0,20}(message|mail|email)",
        r"click.{0,20}(here|below).{0,20}(to|and).{0,20}(validate|verify|confirm|login)",
        r"(password|account).{0,20}(will|would).{0,20}(expire|be.suspended|be.locked)",
    ]
}


def extract_features(payload: EmailPayload,
                     raw_headers: dict = {},
                     safe_browsing_key: str | None = None,
                     abuseipdb_key: str | None = None) -> dict:
    homoglyphs = _unicode_homoglyphs(payload.subject)
    clean_body = _sanitize_text(payload.body_text or "")
    if clean_body.strip().lower() == "missing_data":
        clean_body = ""
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
        "secrecy_request": bool(re.search(r"do not (discuss|mention|tell|share)",
                                          (payload.body_text or "").lower())),
        # New signals tuned for real phishing emails
        "sender_domain_mismatch": _sender_domain_mismatch(payload),
        "phishing_call_to_action": _phishing_call_to_action(payload.subject, clean_body),
        "ml_phishing_score": ml_phishing_score(payload.subject, clean_body),
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
    match = re.match(r'^"?([^"<]+)"?\s*<', payload.sender_email)
    if not match:
        return False
    display_name = match.group(1).strip().lower()
    display_name_normalized = re.sub(r'\s+', '', display_name)  # "micro soft" → "microsoft"
    for trusted in TRUSTED_DOMAINS:
        brand = trusted.split(".")[0]
        if brand in display_name or brand in display_name_normalized:
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


def _sender_domain_mismatch(payload: EmailPayload) -> bool:
    """
    Detects when the display name claims to be a trusted brand
    but the sending domain is completely unrelated.
    E.g. 'USAA' sending from banking2.org, 'PayPal' from 2015p.com.
    Stronger than display_name_spoof — checks the actual domain too.
    """
    match = re.match(r'^"?([^"<]+)"?\s*<', payload.sender_email)
    if not match:
        # Also check subject for brand claims
        display_name = payload.subject.lower()
    else:
        display_name = match.group(1).strip().lower()

    for trusted in TRUSTED_DOMAINS:
        brand = trusted.split(".")[0]
        if brand in display_name:
            # Brand is claimed — now check if domain matches
            if trusted not in payload.sender_domain.lower():
                return True
    return False


# Patterns for direct calls to action — the single strongest text signal
# in credential harvesting phishing emails
CTA_PATTERNS = [
    r"click.{0,20}(here|below|link).{0,30}(verify|validate|confirm|login|update|re.confirm)",
    r"(verify|validate|confirm|update).{0,20}(your|account|email|password|information)",
    r"(login|log in|sign in).{0,20}(to verify|to confirm|to validate|to re.confirm|below)",
    r"(password|account).{0,20}(expire|will expire|expiring)",
    r"(click|follow).{0,20}link.{0,20}(below|provided|above)",
]


def _phishing_call_to_action(subject: str, body: str | None) -> bool:
    """
    Detects direct calls to action that are the hallmark of credential
    harvesting — 'click here to verify', 'password will expire', etc.
    """
    text = (subject + " " + (body or "")).lower()
    return any(re.search(p, text) for p in CTA_PATTERNS)