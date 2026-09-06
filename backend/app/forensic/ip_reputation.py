import os
import ipaddress
import requests


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip_reputation(ip: str) -> dict:

    # Validate IP
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "ip": ip,
            "success": False,
            "error": "Invalid IP address"
        }

    # Skip private/reserved IPs
    if not address.is_global:
        return {
            "ip": ip,
            "success": False,
            "skipped": True,
            "reason": "IP is not a public global address"
        }

    # Get API key
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "ip": ip,
            "success": False,
            "error": "AbuseIPDB API key is not configured"
        }

    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=10
        )

        if response.status_code != 200:
            return {
                "ip": ip,
                "success": False,
                "error": f"AbuseIPDB request failed: {response.status_code}"
            }

        data = response.json().get("data", {})

        return {
            "ip": ip,
            "success": True,
            "abuse_confidence_score": data.get(
                "abuseConfidenceScore"
            ),
            "total_reports": data.get(
                "totalReports"
            ),
            "country_code": data.get(
                "countryCode"
            ),
            "usage_type": data.get(
                "usageType"
            ),
            "isp": data.get(
                "isp"
            ),
            "domain": data.get(
                "domain"
            ),
            "last_reported_at": data.get(
                "lastReportedAt"
            )
        }

    except requests.RequestException as e:
        return {
            "ip": ip,
            "success": False,
            "error": str(e)
        }