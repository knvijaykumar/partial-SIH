import re
from urllib.parse import urlparse


def extract_features(forensics: dict) -> dict:

    headers = forensics.get("headers", {})
    authentication = forensics.get("authentication", {})
    body = forensics.get("body", {})
    urls = forensics.get("urls", [])
    attachments = forensics.get("attachments", [])

    subject = headers.get("subject") or ""
    sender = headers.get("from") or ""
    reply_to = headers.get("reply_to") or ""

    plain_text = body.get("plain_text") or ""
    html_text = body.get("html_text") or ""

    full_text = f"{subject} {plain_text} {html_text}".lower()

    # -----------------------------
    # Authentication features
    # -----------------------------

    spf_fail = int(authentication.get("spf") == "fail")
    dkim_fail = int(authentication.get("dkim") == "fail")
    dmarc_fail = int(authentication.get("dmarc") == "fail")

    # -----------------------------
    # Header anomaly features
    # -----------------------------

    reply_to_mismatch = int(
        reply_to and sender and
        reply_to.lower() not in sender.lower()
    )

    received_headers = headers.get("received", [])

    received_count = len(received_headers)

    # -----------------------------
    # Content features
    # -----------------------------

    urgency_words = [
        "urgent",
        "immediately",
        "action required",
        "verify",
        "suspended",
        "suspension",
        "expire",
        "warning",
        "important"
    ]

    credential_words = [
        "password",
        "login",
        "username",
        "credential",
        "verify your account",
        "sign in"
    ]

    financial_words = [
        "payment",
        "invoice",
        "bank",
        "transaction",
        "transfer",
        "money",
        "account number"
    ]

    urgency_count = sum(
        word in full_text for word in urgency_words
    )

    credential_count = sum(
        word in full_text for word in credential_words
    )

    financial_count = sum(
        word in full_text for word in financial_words
    )

    # -----------------------------
    # URL features
    # -----------------------------

    suspicious_url_count = 0

    for url in urls:

        parsed = urlparse(url)

        hostname = parsed.hostname or ""

        suspicious_patterns = [
            "login",
            "verify",
            "secure",
            "account",
            "update",
            "password"
        ]

        if any(
            pattern in hostname.lower()
            for pattern in suspicious_patterns
        ):
            suspicious_url_count += 1

    # -----------------------------
    # Attachment features
    # -----------------------------

    attachment_count = len(attachments)

    risky_extensions = [
        ".exe",
        ".js",
        ".vbs",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".msi"
    ]

    risky_attachment_count = 0

    for attachment in attachments:

        filename = (
            attachment.get("filename") or ""
        ).lower()

        if any(
            filename.endswith(ext)
            for ext in risky_extensions
        ):
            risky_attachment_count += 1

    # -----------------------------
    # Final ML feature vector
    # -----------------------------

    features = {
        "spf_fail": spf_fail,
        "dkim_fail": dkim_fail,
        "dmarc_fail": dmarc_fail,
        "reply_to_mismatch": reply_to_mismatch,

        "received_count": received_count,

        "url_count": len(urls),
        "suspicious_url_count": suspicious_url_count,

        "attachment_count": attachment_count,
        "risky_attachment_count": risky_attachment_count,

        "urgency_count": urgency_count,
        "credential_count": credential_count,
        "financial_count": financial_count,

        "body_length": len(full_text),
    }

    return features