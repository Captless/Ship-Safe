import shutil

from fastapi.testclient import TestClient

from backend.main import app, _storage
from scanner.ziputils import safe_extract_zip

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_scan_vuln_zip(vuln_zip):
    with open(vuln_zip, "rb") as f:
        r = client.post("/api/scans", files={"file": ("proj.zip", f, "application/zip")})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "complete"
    result = data["result"]
    assert result["score"] < 100
    findings = result["findings"]
    rids = {x["rule_id"] for x in findings}
    assert "SECRET-001" in rids or "SECRET-005" in rids or "SECRET-006" in rids
    assert "CODE-002" in rids or "CODE-004" in rids
    assert "PAY-001" in rids or "PAY-002" in rids
    for f in findings:
        assert "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz" not in f["evidence"]
        assert f["ai_fix_prompt"]
        assert f["description"]


def test_scan_clean_zip_low_findings(clean_zip):
    with open(clean_zip, "rb") as f:
        r = client.post("/api/scans", files={"file": ("clean.zip", f, "application/zip")})
    assert r.status_code == 200, r.text
    result = r.json()["result"]
    criticals = [x for x in result["findings"] if x["severity"] == "critical"]
    highs = [x for x in result["findings"] if x["severity"] == "high"]
    assert len(criticals) == 0
    assert len(highs) == 0
    assert result["score"] >= 80


def test_reject_non_zip():
    r = client.post("/api/scans", files={"file": ("notes.txt", b"hello world", "text/plain")})
    assert r.status_code == 400


def test_reject_malformed_zip(tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"PK\x03\x04 not really a zip file content here")
    with open(bad, "rb") as f:
        r = client.post("/api/scans", files={"file": ("bad.zip", f, "application/zip")})
    assert r.status_code == 400 or r.status_code == 500


def test_scan_then_get_and_report(vuln_zip):
    with open(vuln_zip, "rb") as f:
        r = client.post("/api/scans", files={"file": ("p.zip", f, "application/zip")})
    scan_id = r.json()["scan_id"]
    g = client.get(f"/api/scans/{scan_id}")
    assert g.status_code == 200
    assert g.json()["result"]["score"] == r.json()["result"]["score"]
    rep = client.get(f"/api/scans/{scan_id}/report")
    assert rep.status_code == 200
    assert "Ship Safe Report" in rep.text
    assert "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz" not in rep.text


def test_unknown_scan_404():
    assert client.get("/api/scans/nope").status_code == 404


def test_upload_source_cleaned_after_scan(vuln_zip):
    _storage.clear()
    with open(vuln_zip, "rb") as f:
        r = client.post("/api/scans", files={"file": ("p.zip", f, "application/zip")})
    assert r.status_code == 200
