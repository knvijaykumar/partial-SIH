from fastapi import APIRouter, UploadFile, File, HTTPException
import os
import tempfile

from app.forensic.email_parser import parse_email
from app.forensic.url_analyzer import analyze_url
from app.forensic.ip_analyzer import extract_ips
from app.forensic.ip_intelligence import analyze_ip
from app.forensic.ip_reputation import check_ip_reputation
from app.forensic.domain_intelligence import analyze_domain
from app.forensic.geoip import geolocate_ip
from app.forensic.threat_correlation import correlate_threats
from app.forensic.attack_graph import build_attack_graph
from app.forensic.attachment_analyzer import analyze_attachments

from app.ml.phishing_model import predict_phishing
from app.ml.risk_engine import calculate_risk_score
from app.ml.explainability import generate_explanation

from app.services.investigation_service import save_complete_investigation


router = APIRouter()


@router.post("/analyze-email")
async def analyze_email(file: UploadFile = File(...)):

    # Only allow .eml files
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml email files are supported"
        )

    temp_path = None

    try:
        # 1. Read uploaded email
        contents = await file.read()

        # 2. Create temporary file
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".eml"
        ) as temp_file:
            temp_file.write(contents)
            temp_path = temp_file.name

        # 3. Parse email
        result = parse_email(temp_path)

        headers = result["headers"]
        body = result["body"]

        # 4. Analyze URLs
        url_intelligence = []

        for url in result.get("urls", []):
            url_intelligence.append(
                analyze_url(url)
            )

        # 5. Analyze domains using RDAP
        domain_intelligence = []

        for url_data in url_intelligence:
            domain_intel = url_data.get("domain_intelligence")
            if domain_intel:
                domain_intelligence.append(domain_intel)
            else:
                domain = url_data.get("domain")
                if domain:
                    domain_intelligence.append(
                        analyze_domain(domain)
                    )

        # 6. Extract IP addresses
        ip_addresses = extract_ips(result)

        # 7. Analyze IP addresses
        ip_intelligence = []

        for ip in ip_addresses:
            ip_intelligence.append(
                analyze_ip(ip)
            )

        # 8. Geolocate IP addresses
        geoip_intelligence = []

        for ip in ip_addresses:
            geoip_intelligence.append(
                geolocate_ip(ip)
            )

        # 9. Check IP reputation using AbuseIPDB
        ip_reputation = []

        for ip in ip_addresses:
            ip_reputation.append(
                check_ip_reputation(ip)
            )

        # 10. Analyze attachments
        attachment_intelligence = analyze_attachments(
            result.get("attachments", [])
        )

        # Sanitize forensic attachments to prevent raw byte exposure
        if "attachments" in result:
            sanitized_attachments = []
            for att in result["attachments"]:
                att_copy = {k: v for k, v in att.items() if k != "data"}
                sanitized_attachments.append(att_copy)
            result["attachments"] = sanitized_attachments

        # 11. Combine email body
        full_body = (
            body.get("plain_text", "")
            + " "
            + body.get("html_text", "")
        )

        # 12. AI phishing detection
        ai_prediction = predict_phishing(
            sender=headers.get("from", ""),
            subject=headers.get("subject", ""),
            body=full_body
        )

        # 13. Calculate risk
        risk = calculate_risk_score(
            result,
            ai_prediction
        )

        # 14. Correlate all threat intelligence
        threat_correlation = correlate_threats(
            forensics=result,
            url_intelligence=url_intelligence,
            domain_intelligence=domain_intelligence,
            ip_intelligence=ip_intelligence,
            geoip_intelligence=geoip_intelligence,
            ip_reputation=ip_reputation,
            ai_detection=ai_prediction,
            risk_assessment=risk
        )

        # 15. Generate explainable evidence
        explanation = generate_explanation(
            forensics=result,
            ai_detection=ai_prediction,
            risk_assessment=risk
        )

        # 16. Build forensic attack graph
        attack_graph = build_attack_graph(
            forensics=result,
            url_intelligence=url_intelligence,
            domain_intelligence=domain_intelligence,
            ip_intelligence=ip_intelligence,
            geoip_intelligence=geoip_intelligence,
            ip_reputation=ip_reputation
        )

        # 17. Persist complete investigation to Supabase PostgreSQL database
        investigation_record = save_complete_investigation(
            filename=file.filename,
            forensics=result,
            url_intelligence=url_intelligence,
            domain_intelligence=domain_intelligence,
            ip_intelligence=ip_intelligence,
            geoip_intelligence=geoip_intelligence,
            ip_reputation=ip_reputation,
            attachment_intelligence=attachment_intelligence,
            ai_prediction=ai_prediction,
            risk=risk,
            threat_correlation=threat_correlation,
            explanation=explanation,
            attack_graph=attack_graph,
        )

        # 18. Return complete analysis with investigation_id
        return {
            "status": "success",
            "investigation_id": investigation_record.get("id"),
            "filename": file.filename,

            "forensics": result,

            "url_intelligence": url_intelligence,

            "domain_intelligence": domain_intelligence,

            "ip_intelligence": ip_intelligence,

            "geoip_intelligence": geoip_intelligence,

            "ip_reputation": ip_reputation,

            "attachment_intelligence": attachment_intelligence,

            "ai_detection": ai_prediction,

            "risk_assessment": risk,

            "threat_correlation": threat_correlation,

            "explanation": explanation,

            "attack_graph": attack_graph
        }

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Email analysis failed: {str(e)}"
        )

    finally:
        # Delete temporary file
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)