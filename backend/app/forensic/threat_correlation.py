def correlate_threats(
    forensics: dict,
    url_intelligence: list,
    domain_intelligence: list,
    ip_intelligence: list,
    geoip_intelligence: list,
    ip_reputation: list,
    ai_detection: dict,
    risk_assessment: dict
) -> dict:

    headers = forensics.get("headers", {})

    entities = []

    # Email sender
    sender = headers.get("from")

    if sender:
        entities.append({
            "type": "email",
            "value": sender,
            "role": "sender"
        })

    # URLs
    for url_data in url_intelligence:
        entities.append({
            "type": "url",
            "value": url_data.get("url"),
            "suspicious": url_data.get("suspicious", False)
        })

    # Domains
    for domain_data in domain_intelligence:
        entities.append({
            "type": "domain",
            "value": domain_data.get("domain"),
            "available": domain_data.get("available")
        })

    # IPs
    for ip_data in ip_intelligence:
        entities.append({
            "type": "ip",
            "value": ip_data.get("ip"),
            "public": ip_data.get("public")
        })

    # Threat relationships
    relationships = []

    for url_data in url_intelligence:

        domain = url_data.get("domain")

        if domain:
            relationships.append({
                "source": url_data.get("url"),
                "target": domain,
                "relationship": "resolves_to"
            })

    for ip_data in ip_intelligence:

        ip = ip_data.get("ip")

        if ip:
            relationships.append({
                "source": "email",
                "target": ip,
                "relationship": "originated_from"
            })

    # Evidence summary
    evidence = []

    for reason in risk_assessment.get("reasons", []):
        evidence.append(reason)

    if ai_detection.get("label") == "True":
        evidence.append("AI identified phishing characteristics")

    suspicious_urls = sum(
        1
        for item in url_intelligence
        if item.get("suspicious")
    )

    reported_ips = sum(
        1
        for item in ip_reputation
        if item.get("success")
        and (item.get("abuse_confidence_score") or 0) > 0
    )

    return {
        "entity_count": len(entities),
        "relationship_count": len(relationships),
        "entities": entities,
        "relationships": relationships,
        "indicators": {
            "suspicious_urls": suspicious_urls,
            "reported_ips": reported_ips,
            "ai_phishing_detected": (
                ai_detection.get("label") == "True"
            )
        },
        "evidence": evidence,
        "risk_score": risk_assessment.get("risk_score"),
        "risk_level": risk_assessment.get("risk_level")
    }