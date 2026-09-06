"""
Comprehensive test suite for real forensic URL threat detection module.
Tests benign URLs, authentication URLs on trusted domains, synthetic phishing URLs,
direct IP URLs, userinfo spoofing, and dangerous file download URLs.
"""
from dotenv import load_dotenv
load_dotenv()

from app.forensic.url_analyzer import analyze_url


def test_benign_google_url():
    print("\n--- 1. Testing benign URL: https://www.google.com ---")
    url = "https://www.google.com"
    result = analyze_url(url)
    
    print(f"URL: {result['url']}")
    print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']})")
    print(f"Suspicious: {result['suspicious']}")
    print(f"Indicators: {result['indicators']}")
    print(f"Evidence: {result['evidence']}")
    print(f"Resolved IP: {result['ip_address']}")
    
    assert result["risk_level"] == "LOW", f"Expected LOW, got {result['risk_level']}"
    assert result["suspicious"] is False, "Benign URL should not be marked suspicious"
    assert result["domain"] == "google.com"
    assert result["protocol"] == "https"
    assert result["domain_intelligence"] is not None
    print("[PASS] Benign google.com classified as LOW risk.")


def test_trusted_domain_login_url():
    print("\n--- 2. Testing login on trusted domain: https://accounts.google.com/signin ---")
    url = "https://accounts.google.com/signin"
    result = analyze_url(url)
    
    print(f"URL: {result['url']}")
    print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']})")
    print(f"Suspicious: {result['suspicious']}")
    print(f"Indicators: {result['indicators']}")
    print(f"Evidence: {result['evidence']}")
    
    assert result["risk_level"] == "LOW", f"Expected LOW for trusted platform login, got {result['risk_level']}"
    assert result["suspicious"] is False
    print("[PASS] Legitimate login URL on trusted domain classified as LOW risk without false positives.")


def test_forensic_sample_phishing_url():
    print("\n--- 3. Testing phishing test URL: https://secure-login.suspicious-example.test/verify ---")
    url = "https://secure-login.suspicious-example.test/verify"
    result = analyze_url(url)
    
    print(f"URL: {result['url']}")
    print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']})")
    print(f"Suspicious: {result['suspicious']}")
    print(f"Indicators: {result['indicators']}")
    print(f"Evidence: {result['evidence']}")
    
    assert result["risk_level"] in ("MEDIUM", "HIGH"), f"Expected MEDIUM or HIGH, got {result['risk_level']}"
    assert result["suspicious"] is True
    assert any("login" in ind for ind in result["indicators"]), "Should flag 'login' keyword"
    assert any("verify" in ind for ind in result["indicators"]), "Should flag 'verify' keyword"
    print("[PASS] Phishing URL with credential harvesting keywords correctly detected as suspicious.")


def test_raw_ip_url():
    print("\n--- 4. Testing raw IP URL: http://192.168.1.1/login ---")
    url = "http://192.168.1.1/login"
    result = analyze_url(url)
    
    print(f"URL: {result['url']}")
    print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']})")
    print(f"Suspicious: {result['suspicious']}")
    print(f"Indicators: {result['indicators']}")
    print(f"Structure: {result['structure']}")
    
    assert result["structure"]["is_ip"] is True
    assert result["risk_level"] in ("MEDIUM", "HIGH")
    assert result["suspicious"] is True
    assert any("HTTP" in ind for ind in result["indicators"]), "Should flag unencrypted HTTP"
    assert any("private" in ind for ind in result["indicators"]), "Should flag private IP address"
    print("[PASS] Direct IP URL correctly identified.")


def test_userinfo_spoofing_url():
    print("\n--- 5. Testing userinfo spoofing URL: https://google.com@phishing.test/login ---")
    url = "https://google.com@phishing.test/login"
    result = analyze_url(url)
    
    print(f"URL: {result['url']}")
    print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']})")
    print(f"Indicators: {result['indicators']}")
    
    assert result["structure"]["has_at_symbol"] is True
    assert result["risk_level"] in ("MEDIUM", "HIGH")
    assert any("@" in ind for ind in result["indicators"])
    print("[PASS] Userinfo @ spoofing detected as high risk.")


def test_dangerous_file_download_url():
    print("\n--- 6. Testing executable download URL: http://software-update.test/patch.exe ---")
    url = "http://software-update.test/patch.exe"
    result = analyze_url(url)
    
    print(f"URL: {result['url']}")
    print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']})")
    print(f"Indicators: {result['indicators']}")
    
    assert result["structure"]["has_dangerous_extension"] is True
    assert result["risk_level"] in ("MEDIUM", "HIGH")
    assert any(".exe" in ind for ind in result["indicators"])
    print("[PASS] Dangerous executable payload URL detected.")


def test_url_shortener():
    print("\n--- 7. Testing URL shortener: https://bit.ly/3xyzABC ---")
    url = "https://bit.ly/3xyzABC"
    result = analyze_url(url)
    
    print(f"URL: {result['url']}")
    print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']})")
    print(f"Indicators: {result['indicators']}")
    
    assert result["structure"]["is_shortener"] is True
    assert any("shortening service" in ind for ind in result["indicators"])
    print("[PASS] URL shortener service flagged as obscured destination.")


if __name__ == "__main__":
    print("=======================================================")
    print(" RUNNING REAL FORENSIC URL THREAT DETECTION UNIT TESTS")
    print("=======================================================")
    test_benign_google_url()
    test_trusted_domain_login_url()
    test_forensic_sample_phishing_url()
    test_raw_ip_url()
    test_userinfo_spoofing_url()
    test_dangerous_file_download_url()
    test_url_shortener()
    print("\n=======================================================")
    print(" ALL URL THREAT DETECTION UNIT TESTS PASSED WITH 100% SUCCESS!")
    print("=======================================================")
