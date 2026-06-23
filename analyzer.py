import json
import requests
import config
from typing import Tuple


# Indicator keywords used to build a human-readable reason string.
# NeuralDuo only returns a one-word verdict, so we derive the "why"
# from lightweight heuristics to keep the dashboard's reason column useful.
_URGENCY = ("verify", "confirm", "urgent", "immediately", "click here",
            "act now", "suspended", "expired", "validate", "update your")
_CRED = ("password", "login", "credential", "sign in", "account number")
_LOOKALIKE = ("micr0soft", "amaz0n", "paypa1", "goog1e", "secure-", "-verify",
              "-login", "account-update")


def _derive_reason(sender: str, subject: str, body: str, verdict: str) -> str:
    """Build a short explanation from heuristics (model gives no reason)."""
    blob = f"{sender} {subject} {body}".lower()
    signals = []
    if any(k in blob for k in _URGENCY):
        signals.append("urgency/action language")
    if any(k in blob for k in _CRED):
        signals.append("credential request")
    if any(k in blob for k in _LOOKALIKE):
        signals.append("lookalike domain/keyword")
    if sender.lower().endswith((".tk", ".ml", ".ga", ".cf")):
        signals.append("suspicious TLD")

    if verdict == "PHISHING":
        return ("Model flagged as phishing; indicators: " + ", ".join(signals)) \
            if signals else "Model classified as phishing."
    return ("Model classified as legitimate"
            + (f"; note: {', '.join(signals)}" if signals else "."))


def analyze_email(sender: str, subject: str, body: str) -> Tuple[str, float, str]:
    """Classify an email as phishing/safe using the NeuralDuo model via Ollama.

    NeuralDuo is a single-label classifier: it completes "### Response:" with
    either "phishing" or "legitimate". It does NOT return confidence or a
    reason, so confidence is fixed and reason is heuristically derived.

    Returns:
        (verdict, confidence, reason).
        verdict is "PHISHING", "SAFE", or "UNKNOWN".
        On any failure, returns ("UNKNOWN", 0.0, "parse error").
    """
    url = f"{config.OLLAMA_URL.rstrip('/')}/api/generate"

    # NeuralDuo's EXACT trained prompt format. Do not change this layout --
    # the model was fine-tuned to complete the "### Response:" line.
    email_text = f"From: {sender}\nSubject: {subject}\nBody: {body}"
    prompt = (
        "### Instruction:\n"
        "Classify the email or URL as phishing or legitimate.\n\n"
        f"### Input:\n{email_text}\n\n"
        "### Response:\n"
    )

    payload = {
        "model": config.OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        # Deterministic, single-word output
        "options": {
            "temperature": 0,
            "num_predict": 8,
        },
        # NOTE: no "format": "json" here -- this model emits a bare word,
        # not JSON. Forcing JSON would break it.
    }

    try:
        response = requests.post(url, json=payload, timeout=60)
        response.raise_for_status()

        raw = response.json().get("response", "").strip().lower()

        # The model should say "phishing" or "legitimate". Be tolerant of
        # extra whitespace/tokens around it.
        if "phishing" in raw:
            verdict = "PHISHING"
        elif "legitimate" in raw or "safe" in raw:
            verdict = "SAFE"
        else:
            return "UNKNOWN", 0.0, f"unrecognized output: {raw[:40]}"

        # NeuralDuo gives no probability. We assign a fixed confidence to
        # reflect that this is a deterministic classifier decision, not a
        # calibrated score. Treat it as categorical, not a real probability.
        confidence = 0.95

        reason = _derive_reason(sender, subject, body, verdict)
        return verdict, confidence, reason

    except Exception as e:
        return "UNKNOWN", 0.0, f"parse error: {type(e).__name__}"