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


def decode_mime_header(header_value: str) -> str:
    """Decodes MIME-encoded headers safely to string."""
    if not header_value:
        return ""
    try:
        decoded_parts = decode_header(header_value)
        decoded_text = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                decoded_text.append(part.decode(encoding or 'utf-8', errors='replace'))
            else:
                decoded_text.append(part)
        return "".join(decoded_text)
    except Exception:
        return header_value


def _strip_html(raw: str) -> str:
    """Crudely convert HTML to readable plain text."""
    # Drop <style> and <script> blocks entirely
    raw = re.sub(r"<(style|script)[^>]*>.*?</\1>", " ", raw,
                 flags=re.DOTALL | re.IGNORECASE)
    # Turn <br> and </p> into newlines so structure survives
    raw = re.sub(r"(?i)<br\s*/?>", "\n", raw)
    raw = re.sub(r"(?i)</p>", "\n", raw)
    # Remove all remaining tags
    raw = re.sub(r"<[^>]+>", " ", raw)
    # Unescape HTML entities (&amp; &nbsp; etc.)
    raw = _html.unescape(raw)
    # Collapse whitespace
    raw = re.sub(r"[ \t]+", " ", raw)
    raw = re.sub(r"\n\s*\n+", "\n", raw)
    return raw.strip()


def extract_body(msg: email.message.Message) -> str:
    """Extract readable body text from an email message.

    Prefers text/plain. Falls back to text/html (tags stripped) when no
    plain-text part exists -- which is the case for most marketing, bank,
    and notification emails. Returns first 4000 chars of cleaned text.
    """
    plain_parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" in content_disposition:
                continue
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            except Exception:
                continue
            if content_type == "text/plain":
                plain_parts.append(text)
            elif content_type == "text/html":
                html_parts.append(text)
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace") if payload else ""
        except Exception:
            text = ""
        if content_type == "text/html":
            html_parts.append(text)
        else:
            plain_parts.append(text)

    # Prefer plain text; fall back to stripped HTML
    if plain_parts and "".join(plain_parts).strip():
        body = "\n".join(plain_parts).strip()
    elif html_parts:
        body = _strip_html("\n".join(html_parts))
    else:
        body = ""

    return body[:4000]


def run_cycle() -> None:
    """A single cycle of connecting to IMAP, checking for UNSEEN mail,

    analyzing it, saving to database, and closing the connection.
    """
    if not config.IMAP_HOST or not config.IMAP_USER or not config.IMAP_PASS:
        print("IMAP configuration is incomplete (IMAP_HOST, IMAP_USER, or IMAP_PASS missing). Skipping cycle.")
        return

    imap = None
    try:
        print(f"[{datetime.datetime.now().isoformat()}] Connecting to IMAP host {config.IMAP_HOST}:{config.IMAP_PORT}...")
        imap = imaplib.IMAP4_SSL(config.IMAP_HOST, config.IMAP_PORT)

        print("Logging in...")
        imap.login(config.IMAP_USER, config.IMAP_PASS)

        print("Selecting INBOX...")
        imap.select("INBOX")

        print("Searching for UNSEEN emails...")
        status, messages = imap.uid('search', None, 'UNSEEN')
        if status != 'OK':
            print("Failed to query UNSEEN emails.")
            return

        uids = messages[0].split()
        print(f"Found {len(uids)} unseen email(s).")

        for uid in uids:
            try:
                uid_str = uid.decode()
                # Fetch raw message
                status, data = imap.uid('FETCH', uid, '(RFC822)')
                if status != 'OK' or not data:
                    print(f"Failed to fetch email UID {uid_str}.")
                    continue

                raw_email = None
                for response_part in data:
                    if isinstance(response_part, tuple):
                        raw_email = response_part[1]
                        break

                if not raw_email:
                    print(f"No raw email bytes found for UID {uid_str}.")
                    continue

                # Parse message
                msg = email.message_from_bytes(raw_email)

                # Extract details
                sender = decode_mime_header(msg.get("From", "Unknown Sender"))
                subject = decode_mime_header(msg.get("Subject", "(No Subject)"))
                received_at = decode_mime_header(msg.get("Date", ""))
                if not received_at:
                    received_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

                body = extract_body(msg)

                # Mark as SEEN
                imap.uid('STORE', uid, '+FLAGS', '\\Seen')

                # Analyze email using Ollama
                verdict, confidence, reason = analyzer.analyze_email(sender, subject, body)

                # Save results to DB
                db.insert_email(
                    sender=sender,
                    subject=subject,
                    body=body,
                    verdict=verdict,
                    confidence=confidence,
                    reason=reason,
                    received_at=received_at
                )

                print(f"Processed email | From: {sender} | Subject: {subject} | Verdict: {verdict} | Confidence: {confidence:.2f}")

            except Exception as e:
                print(f"Error processing email UID {uid.decode() if isinstance(uid, bytes) else uid}: {e}")

    except Exception as e:
        print(f"IMAP cycle error: {e}")
    finally:
        if imap:
            try:
                imap.close()
            except Exception:
                pass
            try:
                imap.logout()
            except Exception:
                pass


def main() -> None:
    print("Starting Phishing SIEM Agent...")
    try:
        db.init_db()
    except Exception as e:
        print(f"Failed to initialize database: {e}")

    while True:
        try:
            run_cycle()
        except Exception as e:
            print(f"Unexpected error in run_cycle: {e}")

        print(f"Sleeping for {config.POLL_INTERVAL} seconds...")
        time.sleep(config.POLL_INTERVAL)


if __name__ == '__main__':
    main()