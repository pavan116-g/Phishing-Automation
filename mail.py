"""
mail.py — Comprehensive phishing SIEM test suite.
Tests all 4 detection layers with varied senders, subjects, and content.
"""

import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ── Config ────────────────────────────────────────────────────────────────────
YOUR_GMAIL        = "indragantiteja352@gmail.com"
YOUR_APP_PASSWORD = "zgcp beup fblw jmoz"   # ← replace this
TO                = "indragantiteja352@gmail.com"

# ── Test cases ────────────────────────────────────────────────────────────────
EMAILS = [

    # ── LAYER 1 TESTS: Display-name spoofing ─────────────────────────────────

    {
        "tag":          "L1 - PayPal spoof",
        "from_display": "PayPal Security <noreply@paypal-verify-account.com>",
        "subject":      "Your PayPal account has been limited",
        "html": """
        <p>Dear Customer,</p>
        <p>We've detected unusual activity in your PayPal account.
        Your access has been <strong>temporarily limited</strong>.</p>
        <p>Restore access: <a href="http://primemetricsa.com">Click Here</a></p>
        <p>Failure to verify within 48 hours will result in permanent suspension.</p>
        <p>PayPal Security Team</p>
        """,
    },
    {
        "tag":          "L1 - DHL spoof",
        "from_display": "DHL Express <tracking@dhl-delivery-notification.com>",
        "subject":      "DHL: Your package delivery failed",
        "html": """
        <p>Dear Customer,</p>
        <p>We attempted to deliver your package <strong>#3318250497</strong>
        but were unable to complete delivery.</p>
        <p>Pay ₹35 redelivery fee: <a href="http://hgjbulk.pages.dev">Reschedule Delivery</a></p>
        <p>If we do not hear from you within 48 hours, your package will be returned.</p>
        <p>DHL Customer Support</p>
        """,
    },
    {
        "tag":          "L1 - Microsoft spoof",
        "from_display": "Microsoft Security <alert@microsoft-account-verify.com>",
        "subject":      "Action Required: Verify your Microsoft account now",
        "html": """
        <p>Dear User,</p>
        <p>Your Microsoft account has been flagged for suspicious activity.
        Your account will be <strong>suspended within 24 hours</strong>
        unless you verify your identity.</p>
        <p><a href="http://stfs-bosch.spellencasinogames.com">Verify Account</a></p>
        <p>Microsoft Security Team</p>
        """,
    },

    # ── LAYER 2 TESTS: Typosquat domains ─────────────────────────────────────

    {
        "tag":          "L2 - Typosquat (amaz0n)",
        "from_display": "Amazon <noreply@amaz0n-orders.com>",
        "subject":      "Your Amazon order has been cancelled",
        "html": """
        <p>Dear Customer,</p>
        <p>We were unable to process your recent order due to a payment issue.
        Order <strong>#408-3921847</strong> has been cancelled.</p>
        <p><a href="http://primemetricsa.com">Update Payment Info</a></p>
        <p>Amazon Customer Service</p>
        """,
    },
    {
        "tag":          "L2 - Typosquat (g00gle)",
        "from_display": "Google <security@g00gle-account.com>",
        "subject":      "Suspicious sign-in detected on your Google Account",
        "html": """
        <p>Hi,</p>
        <p>We detected a suspicious sign-in to your Google Account
        from <strong>Kyiv, Ukraine</strong>.</p>
        <p><a href="http://claude-code-docs-site.pages.dev">Secure My Account</a></p>
        <p>Google Security Team</p>
        """,
    },

    # ── LAYER 4 TESTS: ML classifier (passes Layers 1-2-3) ───────────────────

    {
        "tag":          "L4 - Suspicious content (unknown sender)",
        "from_display": "noreply@hgjbulk.pages.dev",
        "subject":      "Your shipment is on hold - urgent action required",
        "html": """
        <p>Your package is currently on hold at our facility.</p>
        <p>To release your shipment, please verify your address
        and pay a small customs fee immediately.</p>
        <p><a href="http://hgjbulk.pages.dev">Release My Package</a></p>
        <p>Failure to act within 24 hours will result in the package being returned.</p>
        """,
    },
    {
        "tag":          "L4 - Credential harvest attempt",
        "from_display": "IT Support <support@primemetricsa.com>",
        "subject":      "Your account password expires today",
        "html": """
        <p>Dear User,</p>
        <p>Your account password is set to expire today.
        Please update your credentials immediately to avoid losing access.</p>
        <p>Username: your email<br>
        Click below to reset your password and sign in with your current credentials.</p>
        <p><a href="http://primemetricsa.com">Update Password Now</a></p>
        """,
    },
    {
        "tag":          "L4 - Financial lure",
        "from_display": "Refunds Team <refunds@abacusnextinternationalldtwtd.vu>",
        "subject":      "You have a pending refund of ₹4,299",
        "html": """
        <p>Dear Customer,</p>
        <p>A refund of <strong>₹4,299</strong> is pending in your account.</p>
        <p>To process your refund, please verify your bank details and KYC information.</p>
        <p><a href="https://abacusnextinternationalldtwtd.vu/$adwclpqdrcomponents@us.bosch.com">
        Claim Refund Now</a></p>
        <p>This offer expires in 24 hours.</p>
        """,
    },

    # ── LEGITIMATE EMAIL TESTS: Should be classified SAFE ────────────────────

    {
        "tag":          "LEGIT - Newsletter",
        "from_display": "Tech Weekly <newsletter@techweekly.io>",
        "subject":      "This week in tech: AI updates and open source news",
        "html": """
        <p>Hello,</p>
        <p>Here's your weekly roundup of the latest in technology:</p>
        <ul>
            <li>New open source LLM released by Meta</li>
            <li>Python 3.13 performance improvements</li>
            <li>Linux kernel 6.10 released</li>
        </ul>
        <p>Have a great week!</p>
        <p>The Tech Weekly Team</p>
        """,
    },
    {
        "tag":          "LEGIT - Order confirmation",
        "from_display": "NutroGarden Orders <orders@nutrogarden.com>",
        "subject":      "Your NutroGarden order #NG-2847 has been confirmed",
        "html": """
        <p>Hi,</p>
        <p>Thank you for your order! Here are your order details:</p>
        <p>Order #NG-2847<br>
        Items: Kitchen Appliance Set<br>
        Total: ₹2,499<br>
        Estimated delivery: 3-5 business days</p>
        <p>We'll send you a tracking number once your order ships.</p>
        <p>NutroGarden Team</p>
        """,
    },
]


def build_email(from_display, subject, html, to):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_display
    msg["To"]      = to
    msg.attach(MIMEText(html, "html"))
    return msg


def main():
    print(f"Connecting to Gmail SMTP...")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(YOUR_GMAIL, YOUR_APP_PASSWORD)
        print(f"Connected. Sending {len(EMAILS)} test emails...\n")

        for i, email in enumerate(EMAILS, 1):
            msg = build_email(
                from_display = email["from_display"],
                subject      = email["subject"],
                html         = email["html"],
                to           = TO,
            )
            smtp.sendmail(email["from_display"], TO, msg.as_string())
            print(f"[{i:02d}/{len(EMAILS)}] [{email['tag']}]")
            print(f"        From: {email['from_display']}")
            print(f"        Subj: {email['subject'][:60]}")
            print()
            time.sleep(3)

    print("="*60)
    print(f"All {len(EMAILS)} emails sent!")
    print("Check dashboard at localhost:5000 in ~30 seconds.")
    print()
    print("Expected results:")
    print("  L1 tests  → PHISHING (display-name spoof)")
    print("  L2 tests  → PHISHING (typosquat domain)")
    print("  L4 tests  → PHISHING (ML classifier)")
    print("  LEGIT tests → SAFE")


if __name__ == "__main__":
    main()