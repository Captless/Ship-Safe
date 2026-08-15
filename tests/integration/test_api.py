import time

from fastapi.testclient import TestClient

from backend.main import app, _storage, _active, ScanState, _report_discovery

client = TestClient(app)


def _poll_scan(scan_id, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/scans/{scan_id}")
        assert r.status_code == 200, r.text
        data = r.json()
        if data["status"] in ("complete", "error"):
            return data
        time.sleep(0.02)
    raise AssertionError(f"scan {scan_id} did not finish within {timeout}s")


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_scan_creates_id_before_completion(vuln_zip):
    with open(vuln_zip, "rb") as f:
        r = client.post("/api/scans", files={"file": ("proj.zip", f, "application/zip")})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["scan_id"]
    assert data["status"] == "running"


def test_scan_vuln_zip(vuln_zip):
    with open(vuln_zip, "rb") as f:
        r = client.post("/api/scans", files={"file": ("proj.zip", f, "application/zip")})
    assert r.status_code == 200, r.text
    data = _poll_scan(r.json()["scan_id"])
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
    result = _poll_scan(r.json()["scan_id"])["result"]
    criticals = [x for x in result["findings"] if x["severity"] == "critical"]
    highs = [x for x in result["findings"] if x["severity"] == "high"]
    assert len(criticals) == 0
    assert len(highs) == 0
    assert result["score"] >= 80


def test_reject_non_zip():
    r = client.post("/api/scans", files={"file": ("notes.txt", b"hello world", "text/plain")})
    assert r.status_code == 400


def test_malformed_zip_yields_error_state(tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"PK\x03\x04 not really a zip file content here")
    with open(bad, "rb") as f:
        r = client.post("/api/scans", files={"file": ("bad.zip", f, "application/zip")})
    assert r.status_code == 200
    data = _poll_scan(r.json()["scan_id"])
    assert data["status"] == "error"
    assert data["error"]


def test_running_scan_returns_progress():
    _active.clear()
    state = ScanState("abc123")
    state.phase = "scanning"
    state.message = "Checking your code"
    state.current = 44
    state.total = 65
    state.current_file = "src/components/Gallery.ts"
    state.files_discovered = 1821
    state.files_skipped = 1756
    state.files_to_scan = 65
    state.files_analyzed = 44
    state.findings_found = 3
    _active["abc123"] = state
    try:
        g = client.get("/api/scans/abc123")
        assert g.status_code == 200
        body = g.json()
        assert body["status"] == "running"
        p = body["progress"]
        assert p["phase"] == "scanning"
        assert p["current"] == 44
        assert p["total"] == 65
        assert p["current_file"] == "src/components/Gallery.ts"
        assert p["files_discovered"] == 1821
        assert p["files_skipped"] == 1756
        assert p["files_to_scan"] == 65
        assert p["files_analyzed"] == 44
        assert p["findings_found"] == 3
    finally:
        _active.clear()


def test_discovery_reporter_updates_state():
    _active.clear()
    state = ScanState("disc123")
    _active["disc123"] = state
    try:
        reporter = _report_discovery(state)
        reporter({"files_discovered": 3, "current_file": "src/app.py"})
        assert state.phase == "discovering"
        assert state.message == "Discovering project files"
        assert state.files_discovered == 3
        assert state.current_file == "src/app.py"
        reporter({"files_discovered": 7, "current_file": "src/app.py"})
        assert state.files_discovered == 7
    finally:
        _active.clear()


def test_active_complete_state_returns_result():
    _active.clear()
    state = ScanState("comp123")
    state.phase = "complete"
    state.status = "complete"
    state.message = "Scan complete"
    state.result = {"score": 72, "grade": "REVIEW BEFORE SHIPPING", "groups": []}
    _active["comp123"] = state
    try:
        g = client.get("/api/scans/comp123")
        assert g.status_code == 200
        body = g.json()
        assert body["status"] == "complete"
        assert body["result"]["score"] == 72
    finally:
        _active.clear()


def test_completed_result_has_completion_fields(vuln_zip):
    with open(vuln_zip, "rb") as f:
        r = client.post("/api/scans", files={"file": ("p.zip", f, "application/zip")})
    result = _poll_scan(r.json()["scan_id"])["result"]
    for key in ("score", "grade", "groups", "application_files", "ignored_files", "duration_ms", "summary"):
        assert key in result


def test_scan_then_get_and_report(vuln_zip):
    with open(vuln_zip, "rb") as f:
        r = client.post("/api/scans", files={"file": ("p.zip", f, "application/zip")})
    scan_id = r.json()["scan_id"]
    polled = _poll_scan(scan_id)
    g = client.get(f"/api/scans/{scan_id}")
    assert g.status_code == 200
    assert g.json()["result"]["score"] == polled["result"]["score"]
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
    _poll_scan(r.json()["scan_id"])
