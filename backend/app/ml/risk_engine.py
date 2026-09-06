def calculate_risk_score(forensics: dict, ai_detection: dict) -> dict:

    authentication = forensics.get("authentication", {})
    headers = forensics.get("headers", {})
    urls = forensics.get("urls", [])
    attachments = forensics.get("attachments", [])

    score = 0
    reasons = []

    # Authentication
    if authentication.get("spf") == "fail":
        score += 15
        reasons.append("SPF authentication failed")

    if authentication.get("dkim") == "fail":
        score += 15
        reasons.append("DKIM authentication failed")

    if authentication.get("dmarc") == "fail":
        score += 15
        reasons.append("DMARC authentication failed")

    # Reply-To mismatch
    sender = headers.get("from") or ""
    reply_to = headers.get("reply_to") or ""

    if sender and reply_to and reply_to.lower() not in sender.lower():
        score += 10
        reasons.append("Reply-To address differs from sender")

    # URLs
    if len(urls) > 0:
        score += 10
        reasons.append("Email contains URL")

    # AI detection
    if ai_detection.get("label") == "True":
        ai_score = ai_detection.get("score", 0)

        score += round(ai_score * 25)

        reasons.append(
            f"AI model detected phishing "
            f"({round(ai_score * 100, 2)}% confidence)"
        )

    # Attachments
    if len(attachments) > 0:
        score += 10
        reasons.append("Email contains attachment")

    # Limit score to 100
    score = min(score, 100)

    # Risk level
    if score >= 75:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }