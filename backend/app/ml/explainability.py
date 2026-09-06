def generate_explanation(
    forensics: dict,
    ai_detection: dict,
    risk_assessment: dict
) -> dict:

    authentication = forensics.get("authentication", {})
    headers = forensics.get("headers", {})
    urls = forensics.get("urls", [])
    attachments = forensics.get("attachments", [])
    body = forensics.get("body", {})

    evidence = []
    positive_signals = []
    negative_signals = []

    # Authentication analysis
    if authentication.get("spf") == "fail":
        evidence.append({
            "category": "Email Authentication",
            "signal": "SPF failed",
            "impact": "high",
            "explanation": (
                "The sending server failed SPF authentication, "
                "which can indicate sender-domain spoofing."
            )
        })
        positive_signals.append("SPF failure")

    if authentication.get("dkim") == "fail":
        evidence.append({
            "category": "Email Authentication",
            "signal": "DKIM failed",
            "impact": "high",
            "explanation": (
                "The email failed DKIM verification, "
                "so its cryptographic sender authentication could not be verified."
            )
        })
        positive_signals.append("DKIM failure")

    if authentication.get("dmarc") == "fail":
        evidence.append({
            "category": "Email Authentication",
            "signal": "DMARC failed",
            "impact": "high",
            "explanation": (
                "The email failed DMARC policy validation, "
                "which is a strong indicator of possible sender impersonation."
            )
        })
        positive_signals.append("DMARC failure")

    # Reply-To analysis
    sender = headers.get("from") or ""
    reply_to = headers.get("reply_to") or ""

    if sender and reply_to:
        if reply_to.lower() not in sender.lower():
            evidence.append({
                "category": "Header Analysis",
                "signal": "Reply-To mismatch",
                "impact": "medium",
                "explanation": (
                    "The Reply-To address differs from the apparent sender, "
                    "which can redirect responses to another mailbox."
                )
            })
            positive_signals.append("Reply-To mismatch")

    # URL analysis
    if urls:
        evidence.append({
            "category": "URL Analysis",
            "signal": f"{len(urls)} URL(s) found",
            "impact": "medium",
            "explanation": (
                "The email contains links that require further "
                "URL and domain investigation."
            )
        })

    # Suspicious URLs
    suspicious_url_count = 0

    for url in urls:
        hostname = ""

        try:
            from urllib.parse import urlparse
            hostname = urlparse(url).hostname or ""
        except Exception:
            pass

        suspicious_keywords = [
            "login",
            "verify",
            "secure",
            "account",
            "password",
            "signin",
            "confirm"
        ]

        if any(
            keyword in hostname.lower()
            for keyword in suspicious_keywords
        ):
            suspicious_url_count += 1

    if suspicious_url_count > 0:
        evidence.append({
            "category": "URL Analysis",
            "signal": "Suspicious URL detected",
            "impact": "high",
            "explanation": (
                "The URL contains characteristics commonly associated "
                "with credential harvesting or account-verification scams."
            )
        })
        positive_signals.append(
            f"{suspicious_url_count} suspicious URL(s)"
        )

    # Attachment analysis
    if attachments:
        evidence.append({
            "category": "Attachment Analysis",
            "signal": f"{len(attachments)} attachment(s) found",
            "impact": "medium",
            "explanation": (
                "The email contains attachments that should be "
                "inspected for potentially malicious content."
            )
        })

    # AI analysis
    if ai_detection.get("label") == "True":

        ai_score = ai_detection.get("score", 0)

        evidence.append({
            "category": "AI Detection",
            "signal": "Phishing detected",
            "impact": "high",
            "explanation": (
                f"The phishing detection model classified the email "
                f"as phishing with a model score of "
                f"{round(ai_score * 100, 2)}%."
            )
        })

        positive_signals.append("AI phishing detection")

    else:
        negative_signals.append(
            "AI model did not detect phishing"
        )

    # Risk assessment
    risk_score = risk_assessment.get("risk_score", 0)
    risk_level = risk_assessment.get("risk_level", "UNKNOWN")

    # Overall explanation
    if risk_level == "HIGH":
        conclusion = (
            "Multiple independent indicators suggest that this email "
            "is potentially malicious and requires investigation."
        )
    elif risk_level == "MEDIUM":
        conclusion = (
            "The email contains suspicious indicators, but additional "
            "investigation is recommended before making a final decision."
        )
    else:
        conclusion = (
            "The available evidence does not currently indicate "
            "a high-risk email."
        )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "conclusion": conclusion,
        "positive_signals": positive_signals,
        "negative_signals": negative_signals,
        "evidence": evidence,
        "explanation_method": "Forensic evidence correlation"
    }