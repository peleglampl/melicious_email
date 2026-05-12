import math

from models import SignalDetail

# Each rule: (feature_key, weight, label, description template, severity)
RULES = [
    (
        "reply_to_mismatch", 25,
        "Reply-To mismatch",
        "Reply-To domain differs from sender domain — a classic social-engineering trick.",
        "high",
    ),
    (
        "lookalike_domain", 30,
        "Lookalike domain",
        "Sender domain closely resembles a trusted brand (edit distance ≤ 3 or homoglyph).",
        "high",
    ),
    (
        "spf_fail", 15,
        "SPF failure",
        "The sending server is not authorised by the domain's SPF record.",
        "medium",
    ),
    (
        "dkim_fail", 15,
        "DKIM failure",
        "The email signature could not be verified — message may have been tampered with.",
        "medium",
    ),
    (
        "dmarc_fail", 10,
        "DMARC failure",
        "DMARC policy check failed — the sender has no domain alignment.",
        "medium",
    ),
    (
        "return_path_mismatch", 10,
        "Return-Path mismatch",
        "Return-Path domain differs from the From address domain.",
        "low",
    ),
    (
        "free_email_sender", 5,
        "Free email provider",
        "Sent from a free webmail provider — weak signal but worth noting.",
        "low",
    ),
    (
        "display_name_spoof", 20,
        "Display name spoofing",
        "Sender display name impersonates a trusted brand but the actual email domain doesn't match.",
        "high",
    ),
    (
    "random_username", 20,
    "Generated sender account",
    "Sender username consists mostly of random digits — typical of throwaway phishing accounts.",
    "high",
    ),
(
    "name_mismatch", 25,
    "Wrong recipient name",
    "Email addresses recipient by a different name — indicates mass phishing campaign with hardcoded names.",
    "high",
),
]


def compute_score(features: dict) -> tuple[float, list[SignalDetail]]:
    """
    Returns (total_score 0-100, list of triggered signals).
    Boolean features fire at their full weight.
    'suspicious_link_count' and 'urgency_score' are continuous.
    """
    signals: list[SignalDetail] = []
    total = 0.0

    for key, weight, label, description, severity in RULES:
        value = features.get(key, False)
        if value:  # bool True or non-zero
            signals.append(SignalDetail(
                name=label,
                score=weight,
                description=description,
                severity=severity,
            ))
            total += weight

    # Continuous: urgency (0–1) → up to 15 pts
    urgency = features.get("urgency_score", 0.0)
    if urgency > 0.1:
        pts = round(urgency * 15, 1)
        signals.append(SignalDetail(
            name="Urgency language",
            score=pts,
            description=f"Subject/body contains urgency-inducing language ({urgency:.0%} of patterns matched).",
            severity="medium" if urgency < 0.5 else "high",
        ))
        total += pts

        # Unicode homoglyphs in subject line
        homoglyphs = features.get("unicode_homoglyphs", [])
        if homoglyphs:
            pts = min(len(homoglyphs) * 10, 25)
            signals.append(SignalDetail(
                name="Unicode homoglyphs in subject",
                score=pts,
                description=f"Subject contains characters that visually mimic Latin letters: {', '.join(homoglyphs[:3])}. Used to bypass keyword filters.",
                severity="high",
            ))
            total += pts

        # Continuous: suspicious links → up to 20 pts
        sus_links = features.get("suspicious_link_count", 0)  # ← back to column 4
        if sus_links > 0:
            pts = min(sus_links * 7, 20)
            signals.append(SignalDetail(
                name="Suspicious links",
                score=pts,
                description=f"{sus_links} link(s) use URL shorteners, raw IPs, or lookalike domains.",
                severity="high" if sus_links >= 2 else "medium",
            ))
            total += pts

        # Confirmed malicious URLs via Google Safe Browsing
        flagged_urls = features.get("flagged_urls", [])  # ← back to column 4
        if flagged_urls:
            pts = min(len(flagged_urls) * 25, 40)
            signals.append(SignalDetail(
                name="Confirmed malicious URLs",
                score=pts,
                description=f"{len(flagged_urls)} link(s) flagged by Google Safe Browsing as malware or phishing.",
                severity="high",
            ))
            total += pts

        # Bad sender IP via AbuseIPDB
        if features.get("bad_sender_ip", False):  # ← back to column 4
            signals.append(SignalDetail(
                name="Malicious sender IP",
                score=30,
                description="The sending server's IP address is flagged in AbuseIPDB — a known spam or attack source.",
                severity="high",
            ))
            total += 30

    # Threat type classification
    threat_types = features.get("threat_types", {})
    if threat_types:
        # Each identified threat type adds points
        pts = min(len(threat_types) * 10, 25)
        type_names = ", ".join(threat_types.keys())
        signals.append(SignalDetail(
            name="Threat pattern detected",
            score=pts,
            description=f"Email content matches known attack patterns: {type_names}.",
            severity="high",
        ))
        total += pts

    # BEC secrecy request — standalone high-weight signal
    if features.get("secrecy_request", False):
        signals.append(SignalDetail(
            name="Secrecy request",
            score=25,
            description="Email asks recipient not to discuss with others — a hallmark of Business Email Compromise.",
            severity="high",
        ))
        total += 25

    # First contact from a domain claiming to be a trusted brand
    if features.get("is_first_contact_from_domain") and features.get("lookalike_domain"):
        signals.append(SignalDetail(
            name="First contact impersonation",
            score=20,
            description="First ever email from this domain, yet it claims to be a trusted brand.",
            severity="high",
        ))
        total += 20

    # Completely unknown sender + financial request
    if not features.get("prior_contact") and features.get("threat_types", {}).get("financial_fraud"):
        signals.append(SignalDetail(
            name="Unknown sender requesting financial action",
            score=25,
            description="No prior contact with this sender, yet the email requests financial action.",
            severity="high",
        ))
        total += 25
    # In scorer.py

    raw = total
    return round(100 / (1 + math.exp(-0.05 * (raw - 50))), 1), signals


def verdict_from_score(score: float, num_signals: int) -> tuple[str, str, str]:
    """Returns (verdict, confidence, recommendation)."""
    if score >= 65:
        verdict = "phishing"
        confidence = "high" if num_signals >= 3 else "medium"
        recommendation = (
            "Do not click any links or download attachments. "
            "Report this email as phishing and delete it."
        )
    elif score >= 45:
        verdict = "suspicious"
        confidence = "medium" if num_signals >= 2 else "low"
        recommendation = (
            "Treat with caution. Verify the sender through an independent channel "
            "before clicking links or providing any information."
        )
    else:
        verdict = "safe"
        confidence = "high" if num_signals == 0 else "medium"
        recommendation = "No significant risk signals detected. Exercise normal caution."

    return verdict, confidence, recommendation
