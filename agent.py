import imaplib
import email
from email.header import decode_header
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

def extract_body(msg: email.message.Message) -> str:
    """Walks the email message parts to extract the plain text body."""
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            # We look for text/plain content that is not an attachment
            if content_type == "text/plain" and "attachment" not in content_disposition:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    pass
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    body_parts.append(payload.decode(charset, errors="replace"))
            except Exception:
                pass
    return "".join(body_parts).strip()

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
