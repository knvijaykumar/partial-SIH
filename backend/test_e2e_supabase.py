import sys
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.core.supabase import get_supabase_client

client = TestClient(app)
supabase = get_supabase_client()


def test_root_and_health():
    print("\n--- 1. Testing GET / and GET /health ---")
    r_root = client.get("/")
    print(f"GET / -> Status: {r_root.status_code}, Body: {r_root.json()}")
    assert r_root.status_code == 200
    assert r_root.json().get("message") == "SIH26106 Backend is running"

    r_health = client.get("/health")
    print(f"GET /health -> Status: {r_health.status_code}, Body: {r_health.json()}")
    assert r_health.status_code == 200
    assert r_health.json().get("status") == "healthy"
    print("[OK] Root & Health checks passed!")


def test_analyze_forensic_sample():
    print("\n--- 2. Testing POST /analyze-email with forensic_sample.eml ---")
    sample_path = Path("test_data/forensic_sample.eml")
    assert sample_path.exists(), "forensic_sample.eml not found"

    with open(sample_path, "rb") as f:
        files = {"file": ("forensic_sample.eml", f, "message/rfc822")}
        resp = client.post("/analyze-email", files=files)

    print(f"Status code: {resp.status_code}")
    if resp.status_code != 200:
        print(f"Error detail: {resp.text}")
        sys.exit(1)

    data = resp.json()
    assert data["status"] == "success"
    inv_id = data.get("investigation_id")
    assert inv_id is not None, "investigation_id missing from response"
    print(f"[OK] Investigation created with ID: {inv_id}")
    print(f"[OK] Risk Score: {data['risk_assessment']['risk_score']} ({data['risk_assessment']['risk_level']})")
    print(f"[OK] AI Detection: {data['ai_detection']}")
    print(f"[OK] Attack Graph nodes: {data['attack_graph']['node_count']}, edges: {data['attack_graph']['edge_count']}")

    # Verify Supabase records
    print("Verifying Supabase records for forensic_sample...")
    inv_row = supabase.table("investigations").select("*").eq("id", inv_id).execute()
    assert len(inv_row.data) == 1, "Investigation not found in DB"
    print(f" - investigations row: OK ({inv_row.data[0]['filename']})")

    forensics_rows = supabase.table("email_forensics").select("*").eq("investigation_id", inv_id).execute()
    assert len(forensics_rows.data) >= 1, "email_forensics not found in DB"
    print(f" - email_forensics rows: {len(forensics_rows.data)} OK")

    url_rows = supabase.table("url_intelligence").select("*").eq("investigation_id", inv_id).execute()
    print(f" - url_intelligence rows: {len(url_rows.data)} OK")

    ip_rows = supabase.table("ip_intelligence").select("*").eq("investigation_id", inv_id).execute()
    print(f" - ip_intelligence rows: {len(ip_rows.data)} OK")

    evidence_rows = supabase.table("forensic_evidence").select("*").eq("investigation_id", inv_id).execute()
    assert len(evidence_rows.data) >= 1, "forensic_evidence not found in DB"
    print(f" - forensic_evidence rows: {len(evidence_rows.data)} OK")

    graph_rows = supabase.table("attack_graphs").select("*").eq("investigation_id", inv_id).execute()
    assert len(graph_rows.data) >= 1, "attack_graphs not found in DB"
    print(f" - attack_graphs rows: {len(graph_rows.data)} OK")

    print("[OK] Forensic Sample E2E test passed!")


def test_analyze_attachment_sample():
    print("\n--- 3. Testing POST /analyze-email with attachment_sample.eml ---")
    sample_path = Path("test_data/attachment_sample.eml")
    assert sample_path.exists(), "attachment_sample.eml not found"

    with open(sample_path, "rb") as f:
        files = {"file": ("attachment_sample.eml", f, "message/rfc822")}
        resp = client.post("/analyze-email", files=files)

    print(f"Status code: {resp.status_code}")
    if resp.status_code != 200:
        print(f"Error detail: {resp.text}")
        sys.exit(1)

    data = resp.json()
    assert data["status"] == "success"
    inv_id = data.get("investigation_id")
    assert inv_id is not None, "investigation_id missing from response"
    print(f"[OK] Investigation created with ID: {inv_id}")
    print(f"[OK] Attachment Intel: {data['attachment_intelligence']}")

    # Verify Supabase records
    print("Verifying Supabase records for attachment_sample...")
    att_rows = supabase.table("attachment_intelligence").select("*").eq("investigation_id", inv_id).execute()
    assert len(att_rows.data) >= 1, "attachment_intelligence not found in DB"
    for att in att_rows.data:
        print(f" - Stored attachment: filename={att['filename']}, sha256={att['sha256']}, size_bytes={att['size_bytes']}")
        assert att["sha256"] is not None and len(att["sha256"]) == 64, "Invalid SHA-256 hash"
        assert "data" not in att, "Raw data should not be present"

    print("[OK] Attachment Sample E2E test passed!")


def test_invalid_file_type():
    print("\n--- 4. Testing POST /analyze-email with non-.eml file ---")
    resp = client.post("/analyze-email", files={"file": ("document.pdf", b"test pdf data", "application/pdf")})
    assert resp.status_code == 400
    print(f"[OK] Successfully rejected non-.eml upload with 400: {resp.json()}")


if __name__ == "__main__":
    test_root_and_health()
    test_analyze_forensic_sample()
    test_analyze_attachment_sample()
    test_invalid_file_type()
    print("\n=======================================================")
    print(" ALL SUPABASE INTEGRATION TESTS PASSED WITH ZERO ERRORS!")
    print("=======================================================")
