import logging
from typing import Any, Dict, List, Optional
from app.core.supabase import get_supabase_client

logger = logging.getLogger("investigation_service")


def create_investigation(investigation_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Creates a new investigation master record in the 'investigations' table.
    """
    client = get_supabase_client()
    payload = {
        "filename": investigation_data.get("filename", "unknown.eml"),
        "subject": investigation_data.get("subject"),
        "sender": investigation_data.get("sender"),
        "recipient": investigation_data.get("recipient"),
        "risk_score": investigation_data.get("risk_score"),
        "risk_level": investigation_data.get("risk_level"),
        "ai_label": str(investigation_data.get("ai_label", "")),
        "ai_score": (
            float(investigation_data["ai_score"])
            if investigation_data.get("ai_score") is not None
            else None
        ),
        "status": investigation_data.get("status", "completed"),
    }

    try:
        response = client.table("investigations").insert(payload).execute()
        if not response.data:
            raise RuntimeError("Database insert returned empty result for investigation")
        return response.data[0]
    except Exception as e:
        logger.error(f"Failed to create investigation: {str(e)}")
        raise RuntimeError(f"Failed to create investigation: {str(e)}") from e


def save_email_forensics(investigation_id: str, forensics_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stores email header, authentication, and body forensics in 'email_forensics'.
    """
    client = get_supabase_client()
    headers = forensics_data.get("headers", {})
    authentication = forensics_data.get("authentication", {})
    body = forensics_data.get("body", {})

    payload = {
        "investigation_id": investigation_id,
        "date": headers.get("date"),
        "reply_to": headers.get("reply_to"),
        "return_path": headers.get("return_path"),
        "message_id": headers.get("message_id"),
        "spf_status": authentication.get("spf"),
        "dkim_status": authentication.get("dkim"),
        "dmarc_status": authentication.get("dmarc"),
        "authentication_results": headers.get("authentication_results"),
        "received_headers": headers.get("received", []),
        "headers": headers,
        "body_plain": body.get("plain_text", ""),
        "body_html": body.get("html_text", ""),
    }

    try:
        response = client.table("email_forensics").insert(payload).execute()
        return response.data[0] if response.data else payload
    except Exception as e:
        logger.error(f"Failed to save email forensics: {str(e)}")
        raise RuntimeError(f"Failed to save email forensics: {str(e)}") from e


def save_url_intelligence(investigation_id: str, url_intelligence_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Stores extracted URL threat intelligence records in 'url_intelligence'.
    """
    if not url_intelligence_list:
        return []

    client = get_supabase_client()
    rows = []
    for item in url_intelligence_list:
        rows.append({
            "investigation_id": investigation_id,
            "url": item.get("url", ""),
            "protocol": item.get("protocol"),
            "hostname": item.get("hostname"),
            "domain": item.get("domain"),
            "port": item.get("port"),
            "path": item.get("path"),
            "suspicious": item.get("suspicious", False),
            "indicators": item.get("indicators", []),
        })

    try:
        response = client.table("url_intelligence").insert(rows).execute()
        return response.data if response.data else rows
    except Exception as e:
        logger.error(f"Failed to save URL intelligence: {str(e)}")
        raise RuntimeError(f"Failed to save URL intelligence: {str(e)}") from e


def save_domain_intelligence(investigation_id: str, domain_intelligence_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Stores RDAP / domain intelligence records in 'domain_intelligence'.
    """
    if not domain_intelligence_list:
        return []

    client = get_supabase_client()
    rows = []
    for item in domain_intelligence_list:
        rows.append({
            "investigation_id": investigation_id,
            "domain": item.get("domain", ""),
            "available": item.get("available", True),
            "handle": item.get("handle"),
            "status": item.get("status", []),
            "events": item.get("events", {}),
            "nameservers": item.get("nameservers", []),
            "error": item.get("error"),
        })

    try:
        response = client.table("domain_intelligence").insert(rows).execute()
        return response.data if response.data else rows
    except Exception as e:
        logger.error(f"Failed to save domain intelligence: {str(e)}")
        raise RuntimeError(f"Failed to save domain intelligence: {str(e)}") from e


def save_ip_intelligence(
    investigation_id: str,
    ip_intelligence_list: List[Dict[str, Any]],
    geoip_intelligence_list: Optional[List[Dict[str, Any]]] = None,
    ip_reputation_list: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """
    Stores IP analysis, geolocation, and AbuseIPDB reputation data in 'ip_intelligence'.
    """
    if not ip_intelligence_list:
        return []

    client = get_supabase_client()
    geoip_map: Dict[str, Dict[str, Any]] = {}
    if geoip_intelligence_list:
        for g in geoip_intelligence_list:
            if g.get("ip"):
                geoip_map[g["ip"]] = g

    rep_map: Dict[str, Dict[str, Any]] = {}
    if ip_reputation_list:
        for r in ip_reputation_list:
            if r.get("ip"):
                rep_map[r["ip"]] = r

    rows = []
    for idx, ip_data in enumerate(ip_intelligence_list):
        ip_addr = ip_data.get("ip", "")
        # Match GeoIP
        geo = geoip_map.get(ip_addr)
        if not geo and geoip_intelligence_list and idx < len(geoip_intelligence_list):
            geo = geoip_intelligence_list[idx]
        geo = geo or {}

        # Match Reputation
        rep = rep_map.get(ip_addr)
        if not rep and ip_reputation_list and idx < len(ip_reputation_list):
            rep = ip_reputation_list[idx]
        rep = rep or {}

        rows.append({
            "investigation_id": investigation_id,
            "ip": ip_addr,
            "version": ip_data.get("version"),
            "public": ip_data.get("public"),
            "private": ip_data.get("private"),
            "loopback": ip_data.get("loopback"),
            "reserved": ip_data.get("reserved"),
            "country": geo.get("country"),
            "country_code": geo.get("country_code"),
            "region": geo.get("region"),
            "city": geo.get("city"),
            "latitude": geo.get("latitude"),
            "longitude": geo.get("longitude"),
            "isp": geo.get("isp"),
            "organization": geo.get("organization"),
            "abuse_confidence_score": rep.get("abuse_confidence_score"),
            "total_reports": rep.get("total_reports"),
            "reputation_error": rep.get("error"),
            "raw_geoip": geo,
            "raw_reputation": rep,
        })

    try:
        response = client.table("ip_intelligence").insert(rows).execute()
        return response.data if response.data else rows
    except Exception as e:
        logger.error(f"Failed to save IP intelligence: {str(e)}")
        raise RuntimeError(f"Failed to save IP intelligence: {str(e)}") from e


def save_attachment_intelligence(
    investigation_id: str,
    attachment_intelligence_list: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Stores attachment metadata and SHA-256 hashes in 'attachment_intelligence'.
    Never stores raw attachment bytes.
    """
    if not attachment_intelligence_list:
        return []

    client = get_supabase_client()
    rows = []
    for item in attachment_intelligence_list:
        rows.append({
            "investigation_id": investigation_id,
            "filename": item.get("filename"),
            "extension": item.get("extension"),
            "content_type": item.get("content_type"),
            "detected_mime_type": item.get("detected_mime_type"),
            "size_bytes": item.get("size_bytes"),
            "sha256": item.get("sha256", ""),
            "risky": item.get("risky", False),
            "indicators": item.get("indicators", []),
        })

    try:
        response = client.table("attachment_intelligence").insert(rows).execute()
        return response.data if response.data else rows
    except Exception as e:
        logger.error(f"Failed to save attachment intelligence: {str(e)}")
        raise RuntimeError(f"Failed to save attachment intelligence: {str(e)}") from e


def save_forensic_evidence(
    investigation_id: str,
    explanation_data: Dict[str, Any],
    threat_correlation_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Stores risk explanations, evidence signals, and threat correlation in 'forensic_evidence'.
    """
    client = get_supabase_client()
    payload = {
        "investigation_id": investigation_id,
        "risk_score": explanation_data.get("risk_score"),
        "risk_level": explanation_data.get("risk_level"),
        "conclusion": explanation_data.get("conclusion"),
        "positive_signals": explanation_data.get("positive_signals", []),
        "negative_signals": explanation_data.get("negative_signals", []),
        "evidence_items": explanation_data.get("evidence", []),
        "explanation_method": explanation_data.get("explanation_method", "Forensic evidence correlation"),
        "threat_correlation": threat_correlation_data or {},
    }

    try:
        response = client.table("forensic_evidence").insert(payload).execute()
        return response.data[0] if response.data else payload
    except Exception as e:
        logger.error(f"Failed to save forensic evidence: {str(e)}")
        raise RuntimeError(f"Failed to save forensic evidence: {str(e)}") from e


def save_attack_graph(investigation_id: str, attack_graph_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stores attack graph nodes, edges, and node counts in 'attack_graphs'.
    """
    client = get_supabase_client()
    payload = {
        "investigation_id": investigation_id,
        "node_count": attack_graph_data.get("node_count", len(attack_graph_data.get("nodes", []))),
        "edge_count": attack_graph_data.get("edge_count", len(attack_graph_data.get("edges", []))),
        "nodes": attack_graph_data.get("nodes", []),
        "edges": attack_graph_data.get("edges", []),
    }

    try:
        response = client.table("attack_graphs").insert(payload).execute()
        return response.data[0] if response.data else payload
    except Exception as e:
        logger.error(f"Failed to save attack graph: {str(e)}")
        raise RuntimeError(f"Failed to save attack graph: {str(e)}") from e


def save_complete_investigation(
    filename: str,
    forensics: Dict[str, Any],
    url_intelligence: List[Dict[str, Any]],
    domain_intelligence: List[Dict[str, Any]],
    ip_intelligence: List[Dict[str, Any]],
    geoip_intelligence: List[Dict[str, Any]],
    ip_reputation: List[Dict[str, Any]],
    attachment_intelligence: List[Dict[str, Any]],
    ai_prediction: Dict[str, Any],
    risk: Dict[str, Any],
    threat_correlation: Dict[str, Any],
    explanation: Dict[str, Any],
    attack_graph: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Orchestrates storing all analysis intelligence into Supabase PostgreSQL tables.
    Returns the created investigation master record.
    """
    headers = forensics.get("headers", {})

    # 1. Create master investigation record
    investigation_record = create_investigation({
        "filename": filename,
        "subject": headers.get("subject"),
        "sender": headers.get("from"),
        "recipient": headers.get("to"),
        "risk_score": risk.get("risk_score"),
        "risk_level": risk.get("risk_level"),
        "ai_label": ai_prediction.get("label"),
        "ai_score": ai_prediction.get("score"),
        "status": "completed",
    })

    investigation_id = investigation_record["id"]

    # 2. Save email forensics
    save_email_forensics(investigation_id, forensics)

    # 3. Save URL intelligence
    if url_intelligence:
        save_url_intelligence(investigation_id, url_intelligence)

    # 4. Save domain intelligence
    if domain_intelligence:
        save_domain_intelligence(investigation_id, domain_intelligence)

    # 5. Save IP intelligence
    if ip_intelligence:
        save_ip_intelligence(
            investigation_id=investigation_id,
            ip_intelligence_list=ip_intelligence,
            geoip_intelligence_list=geoip_intelligence,
            ip_reputation_list=ip_reputation,
        )

    # 6. Save attachment intelligence
    if attachment_intelligence:
        save_attachment_intelligence(investigation_id, attachment_intelligence)

    # 7. Save forensic evidence & explanation
    save_forensic_evidence(
        investigation_id=investigation_id,
        explanation_data=explanation,
        threat_correlation_data=threat_correlation,
    )

    # 8. Save attack graph
    save_attack_graph(investigation_id, attack_graph)

    return investigation_record
