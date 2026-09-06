def build_attack_graph(
    forensics: dict,
    url_intelligence: list,
    domain_intelligence: list,
    ip_intelligence: list,
    geoip_intelligence: list,
    ip_reputation: list
) -> dict:

    nodes = []
    edges = []

    # --------------------------------------------------
    # EMAIL NODE
    # --------------------------------------------------

    email_id = "email_1"

    nodes.append({
        "id": email_id,
        "type": "email",
        "label": "Analyzed Email"
    })

    # --------------------------------------------------
    # SENDER NODE
    # --------------------------------------------------

    sender = forensics.get("headers", {}).get("from")

    if sender:
        sender_id = "sender_1"

        nodes.append({
            "id": sender_id,
            "type": "sender",
            "label": sender
        })

        edges.append({
            "source": email_id,
            "target": sender_id,
            "relationship": "sent_by"
        })

    # --------------------------------------------------
    # REPLY-TO NODE
    # --------------------------------------------------

    reply_to = forensics.get("headers", {}).get("reply_to")

    if reply_to:
        reply_id = "reply_to_1"

        nodes.append({
            "id": reply_id,
            "type": "email",
            "label": reply_to
        })

        edges.append({
            "source": email_id,
            "target": reply_id,
            "relationship": "reply_to"
        })

    # --------------------------------------------------
    # URL + DOMAIN NODES
    # --------------------------------------------------

    for index, url_data in enumerate(url_intelligence):

        url = url_data.get("url")

        if not url:
            continue

        url_id = f"url_{index + 1}"

        nodes.append({
            "id": url_id,
            "type": "url",
            "label": url,
            "suspicious": url_data.get("suspicious", False)
        })

        edges.append({
            "source": email_id,
            "target": url_id,
            "relationship": "contains_url"
        })

        domain = url_data.get("domain")

        if domain:

            domain_id = f"domain_{index + 1}"

            domain_data = {}

            if index < len(domain_intelligence):
                domain_data = domain_intelligence[index]

            nodes.append({
                "id": domain_id,
                "type": "domain",
                "label": domain,
                "available": domain_data.get("available")
            })

            edges.append({
                "source": url_id,
                "target": domain_id,
                "relationship": "uses_domain"
            })

    # --------------------------------------------------
    # IP NODES
    # --------------------------------------------------

    for index, ip_data in enumerate(ip_intelligence):

        ip = ip_data.get("ip")

        if not ip:
            continue

        ip_id = f"ip_{index + 1}"

        nodes.append({
            "id": ip_id,
            "type": "ip",
            "label": ip,
            "public": ip_data.get("public")
        })

        edges.append({
            "source": email_id,
            "target": ip_id,
            "relationship": "received_from"
        })

        # ------------------------------
        # GEOLOCATION
        # ------------------------------

        if index < len(geoip_intelligence):

            geo_data = geoip_intelligence[index]

            if geo_data.get("success"):

                location = (
                    f"{geo_data.get('city')}, "
                    f"{geo_data.get('country')}"
                )

                geo_id = f"geo_{index + 1}"

                nodes.append({
                    "id": geo_id,
                    "type": "location",
                    "label": location
                })

                edges.append({
                    "source": ip_id,
                    "target": geo_id,
                    "relationship": "geolocated_to"
                })

        # ------------------------------
        # ABUSEIPDB
        # ------------------------------

        if index < len(ip_reputation):

            reputation = ip_reputation[index]

            if reputation.get("success"):

                score = reputation.get(
                    "abuse_confidence_score",
                    0
                )

                reputation_id = f"reputation_{index + 1}"

                nodes.append({
                    "id": reputation_id,
                    "type": "threat_intelligence",
                    "label": f"AbuseIPDB: {score}% abuse confidence",
                    "score": score
                })

                edges.append({
                    "source": ip_id,
                    "target": reputation_id,
                    "relationship": "has_reputation"
                })

    # --------------------------------------------------
    # GRAPH SUMMARY
    # --------------------------------------------------

    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges)
    }