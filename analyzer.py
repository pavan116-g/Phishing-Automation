"""
analyzer.py — Multi-layer phishing detection for Phishing-Automation SIEM.

Detection layers (in order):

  1. Dynamic display-name spoof check (no hardcoded brands)
  2. Lookalike / typosquat domain check
  3. SPF + DKIM authentication
  4. cybersectony/phishing-email-detection-distilbert_v2.4.1 classifier
"""

import re
import requests
from difflib import SequenceMatcher
from typing import Tuple

import config

# Lazy-load ML model (loaded once on first use)
_tokenizer  = None
_ml_model   = None

def _get_ml_model():
    global _tokenizer, _ml_model
    if _tokenizer is None or _ml_model is None:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        model_name = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
        _tokenizer = AutoTokenizer.from_pretrained(model_name)
        _ml_model  = AutoModelForSequenceClassification.from_pretrained(model_name)
    return _tokenizer, _ml_model

_SIGNALS: dict[str, tuple] = {
    "urgency / pressure language": (
        "verify", "confirm", "urgent", "immediately", "act now",
        "suspended", "expired", "validate", "update your", "within 24",
        "account will be", "limited time", "click here",
    ),
    "credential / sensitive-info request": (
        "password", "login", "sign in", "credential", "account number",
        "otp", "cvv", "pin", "ssn", "bank details",
    ),
    "financial / payment lure": (
        "refund", "payment failed", "invoice", "wire transfer",
        "transaction", "debited", "credited", "kyc", "reward", "cashback",
    ),
    "lookalike domain keyword": (
        "micr0soft", "amaz0n", "paypa1", "goog1e", "-verify", "-secure",
        "secure-", "-login", "account-update", "verify-",
    ),
}

_KNOWN_LEGIT_PAIRS: dict[str, list[str]] = {
    "hdfc":    ["hdfcbank.com", "hdfcsec.com", "hdfcmf.com"],
    "icici":   ["icicibank.com", "iciciprulife.com"],
    "kotak":   ["kotakbank.com", "kotaksecurities.com"],
    "nippon":  ["nipponindia.com", "nipponindia.email"],
    "motilal": ["motilaloswal.com", "motilaloswalmf.com"],
    "sans":    ["sans.org", "email.sans.org"],
}

_LOOKALIKE_THRESHOLD = 0.82

_COMMON_TLDS = {
    "com", "net", "org", "in", "co", "io", "ai", "info", "biz",
    "bank", "email", "art", "online", "site", "web", "app", "dev", "vu"
}

_BRAND_ROOTS = [
    "google", "gmail", "microsoft", "outlook", "office", "live",
    "amazon", "paypal", "apple", "netflix", "facebook", "instagram",
    "twitter", "linkedin", "dropbox", "github", "adobe", "spotify",
    "flipkart", "zomato", "swiggy", "paytm", "phonepe", "zerodha",
    "groww", "hdfc", "icici", "kotak", "sbi", "axis", "dhl", "fedex",
    "ups", "usps", "ebay", "walmart", "bosch", "samsung", "hp", "dell",
]


def _extract_domain(sender: str) -> str:
    match = re.search(r'<([^>]+)>', sender)
    addr = match.group(1) if match else sender.strip()
    return addr.split("@")[-1].lower().strip() if "@" in addr else addr.lower()


def _extract_display_name(sender: str) -> str:
    match = re.match(r'^"?([^"<]+)"?\s*<', sender)
    return match.group(1).strip().lower() if match else ""


def _get_domain_root(domain: str) -> str:
    parts = domain.split(".")
    while parts and parts[-1] in _COMMON_TLDS:
        parts.pop()
    return parts[-1] if parts else domain.split(".")[0]


def _extract_brand_words(display_name: str) -> list[str]:
    skip = {
        "the", "and", "for", "your", "our", "new", "inc", "ltd",
        "llc", "pvt", "team", "group", "bank", "card", "mail",
        "email", "alert", "support", "service", "services", "notify",
        "notification", "security", "express", "delivery", "account",
        "official", "help", "center", "info", "update", "online",
    }
    words = re.findall(r'[a-z]{3,}', display_name.lower())
    return [w for w in words if w not in skip]


def _check_known_legit_pair(brand_word: str, domain: str) -> bool:
    for key, legit_domains in _KNOWN_LEGIT_PAIRS.items():
        if key in brand_word or brand_word in key:
            if any(domain == d or domain.endswith("." + d) for d in legit_domains):
                return True
    return False


def _dynamic_display_name_spoof(sender: str) -> tuple[bool, str, str]:
    display_name = _extract_display_name(sender)
    domain       = _extract_domain(sender)

    if not display_name:
        return False, "", ""

    brand_words = _extract_brand_words(display_name)
    if not brand_words:
        return False, "", ""

    brand_word = brand_words[0]

    if len(brand_word) < 3:
        return False, "", ""

    if _check_known_legit_pair(brand_word, domain):
        return False, "", ""

    domain_root = _get_domain_root(domain)

    if brand_word == domain_root:
        return False, "", ""

    if domain == brand_word + ".com" or domain.endswith("." + brand_word + ".com"):
        return False, "", ""

    if brand_word in domain_root and domain_root != brand_word:
        return True, brand_word, (
            f"Display name claims '{brand_word}' but sending domain "
            f"'{domain}' appends extra words to the brand name — "
            f"classic typosquat/subdomain spoof attack."
        )

    score = SequenceMatcher(None, brand_word, domain_root).ratio()
    if score >= 0.75:
        return True, brand_word, (
            f"Display name claims '{brand_word}' but sending domain "
            f"'{domain}' (root: '{domain_root}') does not match — "
            f"similarity {score:.0%} suggests impersonation."
        )

    if brand_word not in domain:
        return True, brand_word, (
            f"Display name claims '{brand_word}' but actual sending "
            f"domain '{domain}' has no relation to this brand — "
            f"display-name spoofing attack."
        )

    return False, "", ""


def _is_lookalike(domain: str) -> tuple[bool, str, float]:
    root = _get_domain_root(domain)

    if root in _BRAND_ROOTS:
        return False, "", 0.0

    best_score, best_brand = 0.0, ""
    for brand_root in _BRAND_ROOTS:
        score = SequenceMatcher(None, root, brand_root).ratio()
        if score > best_score:
            best_score = score
            best_brand = brand_root

    if best_score >= _LOOKALIKE_THRESHOLD and root != best_brand:
        return True, best_brand, best_score

    return False, "", 0.0


def _parse_auth_headers(raw_headers: dict) -> dict:
    auth_blob = (
        raw_headers.get("Authentication-Results", "") + " " +
        raw_headers.get("ARC-Authentication-Results", "")
    ).lower()
    spf_header = raw_headers.get("Received-SPF", "").lower()

    def _result(keyword: str) -> bool | None:
        match = re.search(
            rf'{keyword}=(pass|fail|neutral|none|softfail|temperror|permerror)',
            auth_blob
        )
        if not match:
            return None
        return match.group(1) == "pass"

    spf = _result("spf")
    if spf is None and spf_header:
        spf = spf_header.startswith("pass")

    return {
        "spf":     spf,
        "dkim":    _result("dkim"),
        "dmarc":   _result("dmarc"),
        "checked": bool(auth_blob.strip()),
    }


def _build_reason(sender: str, subject: str, body: str, verdict: str) -> str:
    blob = f"{sender} {subject} {body}".lower()
    found = [label for label, kws in _SIGNALS.items()
             if any(k in blob for k in kws)]

    if verdict == "PHISHING":
        if found:
            return "Flagged as phishing. Signals detected: " + "; ".join(found) + "."
        return "Flagged as phishing by ML model. No obvious keyword signals — likely structural / content patterns."
    if verdict == "SAFE":
        if found:
            return ("Classified legitimate. Note: contains "
                    + "; ".join(found)
                    + " — present but not deemed malicious in context.")
        return "Classified legitimate. No suspicious signals detected."
    return "Could not determine a verdict."


def _ml_classify(sender: str, subject: str, body: str) -> tuple[str, float, str]:
    import torch
    try:
        tokenizer, model = _get_ml_model()
        text = f"From: {sender} Subject: {subject} Body: {body[:400]}"
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = model(**inputs)
            probs   = torch.nn.functional.softmax(outputs.logits, dim=-1)
        probs = probs[0].tolist()
        labels = {
            "legitimate_email": probs[0],
            "phishing_url":     probs[1],
            "legitimate_url":   probs[2],
            "phishing_url_alt": probs[3],
        }
        phishing_score = labels["phishing_url"] + labels["phishing_url_alt"]
        legit_score    = labels["legitimate_email"] + labels["legitimate_url"]
        best_label     = max(labels, key=lambda k: labels[k])
        if phishing_score > legit_score:
            return "PHISHING", phishing_score, best_label
        else:
            return "SAFE", legit_score, best_label
    except Exception as e:
        return "UNKNOWN", 0.0, f"ML error: {type(e).__name__}: {e}"


def analyze_email(
    sender:      str,
    subject:     str,
    body:        str,
    raw_headers: dict | None = None,
) -> Tuple[str, float, str]:
    raw_headers = raw_headers or {}
    domain      = _extract_domain(sender)

    # ── Layer 3 FIRST: SPF + DKIM cryptographic check ────────────────────────
    # If the email is cryptographically verified, trust it immediately.
    # No heuristic (display-name, typosquat) overrides a valid DKIM+SPF signature.
    auth    = _parse_auth_headers(raw_headers)
    body_ml = body

    if auth["checked"]:
        spf_pass  = auth["spf"]  is True
        dkim_pass = auth["dkim"] is True
        spf_fail  = auth["spf"]  is False
        dkim_fail = auth["dkim"] is False

        if spf_pass and dkim_pass:
            dmarc_note = "  DMARC ✓" if auth["dmarc"] is True else ""
            return (
                "SAFE", 0.95,
                f"Sender '{domain}' passed SPF ✓ and DKIM ✓{dmarc_note}. "
                f"Email is cryptographically authenticated as legitimate."
            )

        if spf_fail and dkim_fail:
            return (
                "PHISHING", 0.93,
                f"Sender '{domain}' FAILED both SPF and DKIM. "
                f"High likelihood of a spoofed or forged sender."
            )

        if spf_pass and dkim_fail:
            body_ml = f"[SPF pass, DKIM fail — possible content tampering] {body}"
        elif spf_fail and dkim_pass:
            body_ml = f"[SPF fail, DKIM pass — unauthorized relay possible] {body}"

    # ── Layer 1: Dynamic display-name spoof ───────────────────────────────────
    # Only runs if auth was absent or mixed — heuristics as fallback only.
    is_spoof, brand_word, spoof_reason = _dynamic_display_name_spoof(sender)
    if is_spoof:
        return "PHISHING", 0.97, spoof_reason

    # ── Layer 2: Lookalike / typosquat domain ─────────────────────────────────
    is_look, look_brand, look_score = _is_lookalike(domain)
    if is_look:
        return (
            "PHISHING", 0.95,
            f"Sending domain '{domain}' closely resembles '{look_brand}' "
            f"(similarity {look_score:.0%}) but is not a verified "
            f"{look_brand} domain. Likely a typosquat / lookalike attack."
        )

    # Layer 4: DistilBERT ML classifier
    verdict, confidence, raw_label = _ml_classify(sender, subject, body_ml)

    if verdict == "UNKNOWN":
        return "UNKNOWN", 0.0, f"ML error: {raw_label}"

    reason = _build_reason(sender, subject, body_ml, verdict)
    return verdict, round(confidence, 2), reason