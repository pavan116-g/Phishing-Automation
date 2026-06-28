"""
agent.py — IMAP polling agent for Phishing-Automation SIEM.

Connects to Gmail every POLL_INTERVAL seconds, fetches UNSEEN mail,
extracts plain-text body (with HTML fallback), passes raw headers to
analyzer.py for multi-layer detection, and stores results via db.py.
"""

import imaplib
import email
from email.header import decode_header
import re
import html as _html
import time
import datetime
from typing import Tuple

import db
import analyzer
import config


# ── Header decoding ──────────────────────────────────────────────────────────

def decode_mime_header(header_value: str) -> str:
    """Decode a MIME-encoded header value to a plain string."""
    if not header_value:
        return ""
    try:
        parts = decode_header(header_value)
        out = []
        for part, enc in parts:
            if isinstance(part, bytes):
                out.append(part.decode(enc or "utf-8", errors="replace"))
            else:
                out.append(part)
        return "".join(out)
    except Exception:
        return header_value


# ── HTML stripping ───────────────────────────────────────────────────────────

def _strip_html(raw: str) -> str:
    """Convert HTML to readable plain text."""
    # Remove <style> and <script> blocks entirely
    raw = re.sub(r"<(style|script)[^>]*>.*?</\1>", " ",
                 raw, flags=re.DOTALL | re.IGNORECASE)
    # Hidden preheader divs (display:none) — strip their content too
    raw = re.sub(
        r'<div[^>]*display\s*:\s*none[^>]*>.*?</div>', " ",
        raw, flags=re.DOTALL | re.IGNORECASE
    )
    # Block-level tags → newlines
    raw = re.sub(r"(?i)<br\s*/?>", "\n", raw)
    raw = re.sub(r"(?i)</?(p|div|tr|li)[^>]*>", "\n", raw)
    # Remove all remaining tags
    raw = re.sub(r"<[^>]+>", " ", raw)
    # Unescape HTML entities
    raw = _html.unescape(raw)
    # Collapse whitespace
    raw = re.sub(r"[ \t]+", " ", raw)
    raw = re.sub(r"\n\s*\n+", "\n", raw)
    return raw.strip()


# ── Body extraction ──────────────────────────────────────────────────────────

def extract_body(msg: email.message.Message) -> str:
    """
    Extract readable body text from an email message.

    Prefers text/plain. Falls back to text/html (stripped) when no
    plain-text part exists — which covers most marketing / bank /
    notification emails. Returns first 4000 chars of cleaned text.
    """
    plain_parts: list[str] = []
    html_parts:  list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                continue
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            except Exception:
                continue
            if ctype == "text/plain":
                plain_parts.append(text)
            elif ctype == "text/html":
                html_parts.append(text)
    else:
        ctype = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace") if payload else ""
        except Exception:
            text = ""
        if ctype == "text/html":
            html_parts.append(text)
        else:
            plain_parts.append(text)

    if plain_parts and "".join(plain_parts).strip():
        return "\n".join(plain_parts).strip()[:4000]
    if html_parts:
        return _strip_html("\n".join(html_parts))[:4000]
    return ""


# ── Raw header extraction ────────────────────────────────────────────────────

def extract_raw_headers(msg: email.message.Message) -> dict:
    """
    Return a dict of header-name → value for authentication headers.
    These are passed to analyzer.py for SPF/DKIM/DMARC checks.
    """
    auth_headers = [
        "Authentication-Results",
        "ARC-Authentication-Results",
        "Received-SPF",
        "DKIM-Signature",
        "X-Google-DKIM-Signature",
    ]
    return {h: msg.get(h, "") for h in auth_headers}


# ── IMAP polling cycle ───────────────────────────────────────────────────────

def run_cycle() -> None:
    """
    One IMAP cycle: connect, fetch UNSEEN, analyze each email, store result.
    """
    if not config.IMAP_HOST or not config.IMAP_USER or not config.IMAP_PASS:
        print("IMAP configuration incomplete. Skipping cycle.")
        return

    imap = None
    try:
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        print(f"[{ts}] Connecting to {config.IMAP_HOST}:{config.IMAP_PORT}...")
        imap = imaplib.IMAP4_SSL(config.IMAP_HOST, config.IMAP_PORT)
        imap.login(config.IMAP_USER, config.IMAP_PASS)
        imap.select("INBOX")

        status, messages = imap.uid("search", None, "UNSEEN")
        if status != "OK":
            print("Failed to search INBOX.")
            return

        uids = messages[0].split()
        print(f"Found {len(uids)} unseen email(s).")

        for uid in uids:
            uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
            try:
                status, data = imap.uid("FETCH", uid, "(RFC822)")
                if status != "OK" or not data:
                    print(f"  UID {uid_str}: fetch failed.")
                    continue

                raw_email = None
                for part in data:
                    if isinstance(part, tuple):
                        raw_email = part[1]
                        break
                if not raw_email:
                    continue

                msg = email.message_from_bytes(raw_email)

                sender     = decode_mime_header(msg.get("From", "Unknown"))
                subject    = decode_mime_header(msg.get("Subject", "(No Subject)"))
                received_at = decode_mime_header(msg.get("Date", ""))
                if not received_at:
                    received_at = datetime.datetime.now(
                        datetime.timezone.utc).isoformat()

                body        = extract_body(msg)
                raw_headers = extract_raw_headers(msg)

                # Mark as seen before analysis so a crash doesn't re-process
                imap.uid("STORE", uid, "+FLAGS", "\\Seen")

                # Multi-layer analysis (SPF/DKIM → display-name → lookalike → ML)
                verdict, confidence, reason = analyzer.analyze_email(
                    sender, subject, body, raw_headers
                )

                db.insert_email(
                    sender=sender,
                    subject=subject,
                    body=body,
                    verdict=verdict,
                    confidence=confidence,
                    reason=reason,
                    received_at=received_at,
                )

                flag = "🚨" if verdict == "PHISHING" else "✓"
                print(f"  {flag} {verdict:8s} ({confidence*100:.0f}%)  "
                      f"From: {sender[:40]}  |  {subject[:50]}")

            except Exception as e:
                print(f"  UID {uid_str}: error — {e}")

    except Exception as e:
        print(f"IMAP cycle error: {e}")
    finally:
        if imap:
            try: imap.close()
            except Exception: pass
            try: imap.logout()
            except Exception: pass


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    print("Starting Phishing SIEM Agent...")
    try:
        db.init_db()
    except Exception as e:
        print(f"Database init failed: {e}")

    while True:
        try:
            run_cycle()
        except Exception as e:
            print(f"Unexpected error: {e}")
        print(f"Sleeping {config.POLL_INTERVAL}s...\n")
        time.sleep(config.POLL_INTERVAL)


if __name__ == "__main__":
    main()