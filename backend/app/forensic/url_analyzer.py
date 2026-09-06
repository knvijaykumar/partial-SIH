from urllib.parse import urlparse, unquote
import ipaddress
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.forensic.domain_intelligence import analyze_domain
from app.forensic.ip_intelligence import analyze_ip
from app.forensic.ip_reputation import check_ip_reputation
from app.forensic.geoip import geolocate_ip


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "log-in",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "password",
    "passwd",
    "credential",
    "confirm",
    "confirmation",
    "banking",
    "authenticate",
    "authentication",
    "wallet",
    "recover",
    "recovery",
]

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "goo.gl",
    "cutt.ly",
    "rb.gy",
    "shorte.st",
    "tiny.cc",
    "bc.vc",
    "adf.ly",
}

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".msi",
    ".ps1",
    ".vbs",
    ".vbe",
    ".hta",
    ".dll",
    ".jar",
    ".apk",
    ".iso",
    ".img",
}

HIGH_TRUST_DOMAINS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "paypal.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citi.com",
    "adobe.com",
    "dropbox.com",
    "salesforce.com",
    "netflix.com",
    "zoom.us",
    "cloudflare.com",
    "fastapi.tiangolo.com",
    "supabase.com",
}

MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    "co.in", "org.in", "gov.in", "ac.in", "net.in", "gen.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "gov.za",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "com.br", "net.br", "org.br", "gov.br",
}


def extract_domain_from_hostname(hostname: str) -> str:
    """
    Extracts the registered/apex domain from a given hostname.
    E.g.: 'secure-login.suspicious-example.test' -> 'suspicious-example.test'
          'accounts.google.com' -> 'google.com'
          'mail.google.co.uk' -> 'google.co.uk'
          '192.168.1.1' -> '192.168.1.1'
    """
    if not hostname:
        return ""

    hostname_clean = hostname.lower().strip()

    # If it is an IP address, return it directly
    try:
        ipaddress.ip_address(hostname_clean)
        return hostname_clean
    except ValueError:
        pass

    parts = hostname_clean.split(".")
    if len(parts) <= 2:
        return hostname_clean

    # Check for multi-part TLD
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return f"{parts[-3]}.{last_two}"

    return f"{parts[-2]}.{parts[-1]}"


def resolve_hostname_to_ip(hostname: str) -> Optional[str]:
    """
    Resolves hostname to an IPv4 address using DNS resolution.
    Returns None if resolution fails.
    """
    try:
        # Check if already IP
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    try:
        addrinfo = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_INET,
            socket.SOCK_STREAM
        )
        if addrinfo and addrinfo[0][4]:
            return addrinfo[0][4][0]
    except (socket.gaierror, socket.timeout, Exception):
        return None

    return None


def parse_date_safe(date_str: str) -> Optional[datetime]:
    """
    Safely parses ISO date string from RDAP events.
    """
    if not date_str:
        return None
    try:
        # Handle '1997-09-15T04:00:00Z'
        clean = date_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        return None


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Performs forensic threat analysis on a URL using real evidence:
    - Protocol & scheme security
    - Hostname & domain extraction
    - Structural anomaly detection (direct IPs, @ spoofing, shorteners, unusual ports, homographs)
    - Sensitive keyword detection (evaluated as evidence indicators)
    - Real RDAP domain intelligence
    - Real IP intelligence, GeoIP, and AbuseIPDB reputation
    - Explainable risk scoring & classification (LOW, MEDIUM, HIGH)
    """
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    raw_netloc = parsed.netloc or ""
    hostname = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or ""
    query = parsed.query or ""

    domain = extract_domain_from_hostname(hostname)

    indicators: List[str] = []
    evidence: List[str] = []
    score: int = 0

    # --------------------------------------------------
    # 1. Structural & Protocol Analysis
    # --------------------------------------------------
    is_https = scheme == "https"
    is_http = scheme == "http"

    if is_http:
        score += 15
        indicators.append("URL does not use HTTPS (unencrypted plain HTTP)")
    elif not is_https:
        score += 35
        indicators.append(f"URL uses uncommon/potentially unsafe protocol: {scheme}")

    # Check for Userinfo / '@' spoofing in netloc
    has_at_symbol = "@" in raw_netloc
    if has_at_symbol:
        score += 40
        indicators.append("URL contains '@' userinfo character in authority (potential destination spoofing)")

    # Check if hostname is a raw IP
    is_raw_ip = False
    is_private_ip = False
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_raw_ip = True
        is_private_ip = not ip_obj.is_global
        if is_private_ip:
            score += 20
            indicators.append(f"URL targets a private/internal network IP address ({hostname})")
        else:
            score += 35
            indicators.append(f"URL uses a direct public IP address instead of a domain name ({hostname})")
    except ValueError:
        is_raw_ip = False

    # Check for URL Shorteners
    is_shortener = domain in URL_SHORTENERS
    if is_shortener:
        score += 20
        indicators.append(f"URL uses known shortening service ({domain}) which obscures destination")

    # Check for Punycode / IDN Homograph attack
    has_punycode = "xn--" in hostname.lower()
    if has_punycode:
        score += 35
        indicators.append(f"Hostname uses punycode/IDN homograph encoding ({hostname})")

    # Check for Non-standard Port
    has_unusual_port = False
    if port and port not in (80, 443, 8080, 8443):
        score += 15
        has_unusual_port = True
        indicators.append(f"URL specifies non-standard network port ({port})")

    # Check for Dangerous Executable Payload in Path
    has_dangerous_ext = False
    path_lower = path.lower()
    for ext in DANGEROUS_EXTENSIONS:
        if path_lower.endswith(ext) or f"{ext}?" in path_lower:
            score += 40
            has_dangerous_ext = True
            indicators.append(f"URL points directly to an executable/script payload ({ext})")
            break

    # Subdomain depth analysis
    subdomain_parts = hostname.replace(domain, "").strip(".").split(".")
    subdomain_count = len([p for p in subdomain_parts if p])
    if subdomain_count >= 3:
        score += 10
        indicators.append(f"Hostname contains {subdomain_count} nested subdomain levels")

    # --------------------------------------------------
    # 2. Sensitive Keyword Analysis
    # --------------------------------------------------
    is_high_trust = domain in HIGH_TRUST_DOMAINS and not has_at_symbol and not has_punycode

    subdomain_hostname_str = hostname.lower()
    path_query_str = f"{path_lower}?{query.lower()}"

    matched_subdomain_keywords = []
    matched_path_keywords = []

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in subdomain_hostname_str and not is_raw_ip:
            # Check if it is not just the high-trust apex domain name itself
            if kw in domain and is_high_trust:
                pass
            else:
                matched_subdomain_keywords.append(kw)
        if kw in path_query_str:
            matched_path_keywords.append(kw)

    if matched_subdomain_keywords:
        if is_high_trust:
            indicators.append(
                f"Sensitive keyword(s) '{', '.join(matched_subdomain_keywords)}' present on verified platform ({domain})"
            )
        else:
            score += 25
            indicators.append(
                f"Suspicious keyword(s) '{', '.join(matched_subdomain_keywords)}' present in hostname/subdomain"
            )

    if matched_path_keywords:
        if is_high_trust:
            indicators.append(
                f"Operational authentication keyword(s) '{', '.join(matched_path_keywords)}' in path on verified platform ({domain})"
            )
        else:
            score += 10
            indicators.append(
                f"Sensitive keyword(s) '{', '.join(matched_path_keywords)}' present in URL path/query"
            )

    # --------------------------------------------------
    # 3. Domain Intelligence (RDAP)
    # --------------------------------------------------
    domain_intel: Optional[Dict[str, Any]] = None
    if not is_raw_ip and domain:
        domain_intel = analyze_domain(domain)
        if domain_intel.get("available"):
            events = domain_intel.get("events", {})
            reg_date_str = events.get("registration")
            if reg_date_str:
                reg_dt = parse_date_safe(reg_date_str)
                if reg_dt:
                    now = datetime.now(timezone.utc)
                    age_days = (now - reg_dt).days
                    if age_days < 30:
                        score += 30
                        indicators.append(f"Domain is newly registered ({age_days} days old, registered {reg_date_str})")
                    elif age_days < 90:
                        score += 15
                        indicators.append(f"Domain was registered recently ({age_days} days old, registered {reg_date_str})")
        else:
            error_msg = domain_intel.get("error", "RDAP unavailable")
            # If domain RDAP is completely failing / not found on an unknown domain
            if not is_high_trust:
                score += 15
                indicators.append(f"Domain RDAP intelligence unavailable ({error_msg})")

    # --------------------------------------------------
    # 4. IP Resolution, IP Intelligence, GeoIP, AbuseIPDB
    # --------------------------------------------------
    resolved_ip: Optional[str] = None
    ip_intel: Optional[Dict[str, Any]] = None
    geoip_intel: Optional[Dict[str, Any]] = None
    ip_rep: Optional[Dict[str, Any]] = None

    if is_raw_ip:
        resolved_ip = hostname
    else:
        resolved_ip = resolve_hostname_to_ip(hostname)

    if resolved_ip:
        ip_intel = analyze_ip(resolved_ip)
        geoip_intel = geolocate_ip(resolved_ip)

        if ip_intel.get("public"):
            ip_rep = check_ip_reputation(resolved_ip)
            if ip_rep.get("success"):
                abuse_score = ip_rep.get("abuse_confidence_score") or 0
                total_reports = ip_rep.get("total_reports") or 0
                if abuse_score > 50:
                    score += 50
                    indicators.append(
                        f"Resolved IP {resolved_ip} has high AbuseIPDB abuse confidence score of {abuse_score}% ({total_reports} reports)"
                    )
                elif abuse_score > 0:
                    score += 25
                    indicators.append(
                        f"Resolved IP {resolved_ip} has AbuseIPDB abuse confidence score of {abuse_score}% ({total_reports} reports)"
                    )
                else:
                    evidence.append(
                        f"Resolved IP {resolved_ip} has 0 reported abuse incidents in AbuseIPDB (absence of reports does not guarantee safety)"
                    )
            elif ip_rep.get("error"):
                evidence.append(f"AbuseIPDB reputation query status: {ip_rep.get('error')}")
    else:
        if not is_raw_ip and hostname:
            if not is_high_trust:
                score += 15
                indicators.append("DNS resolution failed: hostname does not resolve to an active IP address")
            else:
                evidence.append("DNS lookup did not return an immediate IP record")

    # --------------------------------------------------
    # 5. Risk Assessment & Explainable Evidence Formulation
    # --------------------------------------------------
    if is_high_trust and not has_at_symbol and not has_punycode and not has_dangerous_ext:
        # Prevent false positives on verified platforms
        score = min(score, 20)

    score = max(0, min(score, 100))

    if score >= 60:
        risk_level = "HIGH"
        risk_classification = "HIGH"
        suspicious = True
        evidence.append("Multiple high-risk forensic indicators detected indicating potential phishing, payload delivery, or credential harvesting.")
    elif score >= 25:
        risk_level = "MEDIUM"
        risk_classification = "MEDIUM"
        suspicious = True
        evidence.append("Suspicious structural or domain indicators detected requiring caution and further inspection.")
    else:
        risk_level = "LOW"
        risk_classification = "LOW"
        suspicious = len(indicators) > 0 and not is_high_trust
        if is_high_trust:
            evidence.append(f"URL belongs to established, trusted domain ({domain}) with valid infrastructure.")
        else:
            evidence.append("No critical threat indicators or active abuse records identified.")

    return {
        "url": url,
        "protocol": parsed.scheme,
        "hostname": hostname,
        "domain": domain,
        "port": port,
        "path": path,
        "suspicious": suspicious,
        "risk_level": risk_level,
        "risk_classification": risk_classification,
        "risk_score": score,
        "indicators": indicators,
        "evidence": evidence,
        "structure": {
            "is_ip": is_raw_ip,
            "is_shortener": is_shortener,
            "has_at_symbol": has_at_symbol,
            "has_dangerous_extension": has_dangerous_ext,
            "subdomain_count": subdomain_count,
            "query": query,
            "is_https": is_https,
        },
        "domain_intelligence": domain_intel,
        "ip_address": resolved_ip,
        "ip_intelligence": ip_intel,
        "geoip_intelligence": geoip_intel,
        "ip_reputation": ip_rep,
    }