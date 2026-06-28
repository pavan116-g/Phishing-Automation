"""
test_suite.py — Realistic phishing & legitimate email test suite.
Directly calls analyze_email() — no SMTP needed.
Tests all 4 detection layers with realistic content.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import analyze_email

# ── ANSI colors ───────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ─────────────────────────────────────────────────────────────────────────────
# TEST CASES
# Each has: tag, expected, sender, subject, body, headers
# ─────────────────────────────────────────────────────────────────────────────
TESTS = [

    # ══════════════════════════════════════════════════════════════════════════
    # PHISHING EMAILS — Realistic, look like legit
    # ══════════════════════════════════════════════════════════════════════════

    {
        "tag":      "PHISH — PayPal account limited",
        "expected": "PHISHING",
        "layer":    "L1",
        "sender":   "PayPal <service@paypal-secure-login.com>",
        "subject":  "Your PayPal account has been temporarily limited",
        "body":     """
Dear Customer,

We noticed some unusual activity in your PayPal account and have
temporarily limited your access as a security precaution.

What this means:
- You can't send or receive money
- You can't withdraw funds

To restore your account, please verify your identity by clicking
the link below within 24 hours, or your account will be permanently suspended.

https://paypal-secure-login.com/verify?token=ae3f91bc

Reference ID: PP-2847-5591-3301
PayPal Account Services
""",
        "headers": {},
    },

    {
        "tag":      "PHISH — Microsoft sign-in alert",
        "expected": "PHISHING",
        "layer":    "L1",
        "sender":   "Microsoft Account Team <no-reply@microsoft-account-verify.com>",
        "subject":  "Unusual sign-in activity on your Microsoft account",
        "body":     """
Microsoft account
Unusual sign-in activity

We detected something unusual about a recent sign-in to the Microsoft
account.

Sign-in details:
Country/region: Russia
IP address: 185.220.101.47
Platform: Windows
Browser: Chrome

If this was you, you can ignore this message.
If you didn't sign in recently, your account may be compromised.
Please review your recent activity and secure your account.

https://microsoft-account-verify.com/security?ref=8821

The Microsoft account team
""",
        "headers": {},
    },

    {
        "tag":      "PHISH — HDFC Bank KYC",
        "expected": "PHISHING",
        "layer":    "L1",
        "sender":   "HDFC Bank <alerts@hdfc-netbanking-update.com>",
        "subject":  "Important: Complete your KYC verification to avoid account suspension",
        "body":     """
Dear Valued Customer,

As per RBI guidelines, all customers are required to complete their
KYC (Know Your Customer) verification by 30th June 2026.

Your HDFC Bank account will be temporarily suspended if KYC is not
completed within the next 48 hours.

Steps to complete KYC:
1. Click on the secure link below
2. Enter your account details
3. Upload your Aadhaar and PAN card
4. Submit OTP verification

Complete KYC Now: https://hdfc-netbanking-update.com/kyc-verify

For assistance, contact: support@hdfc-netbanking-update.com

Regards,
HDFC Bank Customer Care
""",
        "headers": {},
    },

    {
        "tag":      "PHISH — Amazon order cancelled",
        "expected": "PHISHING",
        "layer":    "L2",
        "sender":   "Amazon <order-update@amaz0n-orders.in>",
        "subject":  "Your Amazon order #408-8821047-2938571 has been cancelled",
        "body":     """
Hello,

We're sorry to inform you that your recent Amazon order has been
cancelled due to a payment verification failure.

Order Details:
Order #408-8821047-2938571
Item: Samsung Galaxy S24 Ultra (256GB)
Amount: ₹1,24,999

To reinstate your order and secure your item before it goes out of
stock, please update your payment information immediately.

Update Payment: https://amaz0n-orders.in/payment-update

This link expires in 12 hours.

Amazon Customer Service
""",
        "headers": {},
    },

    {
        "tag":      "PHISH — SBI SPF+DKIM fail",
        "expected": "PHISHING",
        "layer":    "L3",
        "sender":   "SBI NetBanking <alerts@sbi-secure.net>",
        "subject":  "SBI Alert: Your account has been debited ₹45,000",
        "body":     """
Dear SBI Customer,

A transaction of ₹45,000 has been debited from your account ending
in XXXX2847 on 28/06/2026 at 11:42 AM.

Transaction Details:
Amount: ₹45,000
Merchant: International Transfer
Reference: SBI2826478821

If you did not authorize this transaction, please click the link
below immediately to dispute and reverse this transaction.

Dispute Transaction: https://sbi-secure.net/dispute?ref=SBI2826478821

SBI Customer Care
Toll Free: 1800-112-211
""",
        "headers": {"Authentication-Results": "spf=fail dkim=fail"},
    },

    {
        "tag":      "PHISH — DHL package on hold",
        "expected": "PHISHING",
        "layer":    "L4",
        "sender":   "noreply@dhl-parcel-notification.net",
        "subject":  "DHL Express: Your parcel is on hold — customs fee required",
        "body":     """
DHL EXPRESS NOTIFICATION

Your parcel with tracking number JD014600004958837 is currently
being held at our customs facility.

Reason: Import duty payment required

Parcel Details:
From: United Kingdom
Weight: 1.2 kg
Declared value: £85.00

To release your parcel, a customs duty of ₹450 must be paid
within 5 business days, otherwise the parcel will be returned
to the sender.

Pay customs fee: https://dhl-parcel-notification.net/customs/pay

DHL Express Customer Service
""",
        "headers": {"Authentication-Results": "spf=fail dkim=pass"},
    },

    {
        "tag":      "PHISH — Google Drive shared doc",
        "expected": "PHISHING",
        "layer":    "L4",
        "sender":   "drive-noreply@googledrive-share.com",
        "subject":  "Pavanteja shared a document with you",
        "body":     """
Pavanteja Indraganti has shared the following document with you:

Document: Q2 2026 Salary Revision - Confidential.pdf

To view this document, you'll need to sign in to your Google account.

View Document: https://googledrive-share.com/docs/view?id=8821bc

This document will expire in 24 hours.

Google Drive
""",
        "headers": {"Authentication-Results": "spf=fail dkim=pass"},
    },

    # ══════════════════════════════════════════════════════════════════════════
    # LEGITIMATE EMAILS — Should be classified SAFE
    # ══════════════════════════════════════════════════════════════════════════

    {
        "tag":      "LEGIT — Google security alert",
        "expected": "SAFE",
        "layer":    "L3",
        "sender":   "Google <no-reply@accounts.google.com>",
        "subject":  "Security alert for your linked Google Account",
        "body":     """
Your Google Account was just signed in to from a new device.

Device: MacBook Pro
Location: Hyderabad, Telangana, India
Time: Tuesday, June 28, 2026, 10:30 AM IST

If this was you, you don't need to do anything.

If you didn't sign in recently, check your account activity at
https://myaccount.google.com/

The Google Accounts team
""",
        "headers": {"Authentication-Results": "spf=pass dkim=pass"},
    },

    {
        "tag":      "LEGIT — PayPal receipt",
        "expected": "SAFE",
        "layer":    "L3",
        "sender":   "PayPal <service@paypal.com>",
        "subject":  "You sent a payment of ₹2,499.00",
        "body":     """
Hello,

You sent a payment of ₹2,499.00 to Swiggy India Pvt Ltd.

Transaction Details:
Transaction ID: 8WM34567KX8901234
Date: June 28, 2026
Amount: ₹2,499.00
Merchant: Swiggy India Pvt Ltd

If you didn't authorize this transaction, contact us immediately
at https://www.paypal.com/disputes

Thanks for using PayPal.
PayPal
""",
        "headers": {"Authentication-Results": "spf=pass dkim=pass"},
    },

    {
        "tag":      "LEGIT — SANS newsletter",
        "expected": "SAFE",
        "layer":    "L3",
        "sender":   "SANS NewsBites <newsbites@sans.org>",
        "subject":  "SANS NewsBites Vol. 28 Num. 50: Critical OpenSSL Vulnerability",
        "body":     """
SANS NewsBites | Vol. 28 Num. 50

TOP OF THE NEWS

--Critical Vulnerability Found in OpenSSL 3.x
A high-severity vulnerability (CVE-2026-1234) has been discovered
in OpenSSL 3.x that could allow remote code execution. Users are
advised to upgrade to OpenSSL 3.3.2 immediately.

--CISA Adds 5 New CVEs to Known Exploited Vulnerabilities Catalog
The Cybersecurity and Infrastructure Security Agency (CISA) has
added five new vulnerabilities to its KEV catalog, including
flaws in Cisco IOS XE and Fortinet FortiOS.

--Ransomware Group Claims Attack on European Healthcare Provider
A major European hospital network confirmed a ransomware attack
affecting patient records systems across 12 facilities.

Read the full edition at https://www.sans.org/newsletters/newsbites/

SANS Internet Storm Center: https://isc.sans.edu/
""",
        "headers": {"Authentication-Results": "spf=pass dkim=pass"},
    },

    {
        "tag":      "LEGIT — Zerodha account statement",
        "expected": "SAFE",
        "layer":    "L3",
        "sender":   "Zerodha <no-reply@zerodha.com>",
        "subject":  "Your June 2026 account statement is ready",
        "body":     """
Hi Pavanteja,

Your account statement for June 2026 is now available on Kite.

Summary:
Opening Balance: ₹1,24,500.00
Closing Balance: ₹1,38,750.00
Net P&L: +₹14,250.00
Total Trades: 23

You can download your statement from:
Console > Reports > Account Statement

For any queries, visit https://support.zerodha.com

Happy investing,
Team Zerodha
""",
        "headers": {"Authentication-Results": "spf=pass dkim=pass"},
    },

    {
        "tag":      "LEGIT — Swiggy order confirmed",
        "expected": "SAFE",
        "layer":    "L4",
        "sender":   "Swiggy <no-reply@swiggy.in>",
        "subject":  "Your order from Burger King has been placed!",
        "body":     """
Hey Pavanteja!

Your order has been placed successfully.

Order Details:
Restaurant: Burger King — Jubilee Hills
Items:
  - Whopper Meal (Large) x1 — ₹349
  - Crispy Veg Burger x1 — ₹149
  - Chocolate Shake x1 — ₹129

Order Total: ₹627 (incl. delivery fee & taxes)
Estimated Delivery: 35-40 mins

Track your order on the Swiggy app.

Bon appétit!
Team Swiggy
""",
        "headers": {"Authentication-Results": "spf=pass dkim=fail"},
    },

]


# ─────────────────────────────────────────────────────────────────────────────
# RUN TESTS
# ─────────────────────────────────────────────────────────────────────────────

def run():
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  PHISH SIEM — Realistic Email Test Suite{RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")

    passed = 0
    failed = 0
    results = []

    for t in TESTS:
        verdict, confidence, reason = analyze_email(
            t["sender"], t["subject"], t["body"].strip(), t["headers"]
        )

        correct = verdict == t["expected"]
        if correct:
            passed += 1
        else:
            failed += 1

        results.append({**t, "verdict": verdict, "confidence": confidence,
                        "reason": reason, "correct": correct})

    # ── Print results ─────────────────────────────────────────────────────────
    phishing_tests = [r for r in results if r["expected"] == "PHISHING"]
    legit_tests    = [r for r in results if r["expected"] == "SAFE"]

    print(f"{BOLD}{RED}PHISHING TESTS{RESET}")
    print(f"{DIM}{'─'*70}{RESET}")
    for r in phishing_tests:
        icon = f"{GREEN}✅{RESET}" if r["correct"] else f"{RED}❌{RESET}"
        verdict_color = RED if r["verdict"] == "PHISHING" else (GREEN if r["verdict"] == "SAFE" else YELLOW)
        print(f"{icon} {BOLD}{r['tag']}{RESET}  [{DIM}{r['layer']}{RESET}]")
        print(f"   Verdict    : {verdict_color}{r['verdict']}{RESET} ({r['confidence']:.0%})")
        print(f"   Reason     : {DIM}{r['reason'][:90]}{'...' if len(r['reason'])>90 else ''}{RESET}")
        print()

    print(f"{BOLD}{GREEN}LEGITIMATE TESTS{RESET}")
    print(f"{DIM}{'─'*70}{RESET}")
    for r in legit_tests:
        icon = f"{GREEN}✅{RESET}" if r["correct"] else f"{RED}❌{RESET}"
        verdict_color = GREEN if r["verdict"] == "SAFE" else (RED if r["verdict"] == "PHISHING" else YELLOW)
        print(f"{icon} {BOLD}{r['tag']}{RESET}  [{DIM}{r['layer']}{RESET}]")
        print(f"   Verdict    : {verdict_color}{r['verdict']}{RESET} ({r['confidence']:.0%})")
        print(f"   Reason     : {DIM}{r['reason'][:90]}{'...' if len(r['reason'])>90 else ''}{RESET}")
        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    total = len(results)
    pct   = (passed / total) * 100

    print(f"{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  RESULTS: {GREEN}{passed} passed{RESET} / {RED}{failed} failed{RESET} / {total} total  ({pct:.0f}% accuracy){RESET}")

    fp = sum(1 for r in legit_tests    if r["verdict"] == "PHISHING")
    fn = sum(1 for r in phishing_tests if r["verdict"] == "SAFE")
    print(f"  False Positives (legit flagged as phishing) : {RED}{fp}{RESET}")
    print(f"  False Negatives (phishing missed)           : {RED}{fn}{RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")


if __name__ == "__main__":
    run()