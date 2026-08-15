from scanner.models import FileSnapshot
from scanner.engine import scan_root, group_findings
from scanner.models import Finding, Severity, Confidence


def _fs(path, content):
    return FileSnapshot(path=path, content=content)


def _finding(rid, sev, conf, file, category="x", evidence="e"):
    return Finding(
        rule_id=rid, severity=sev, confidence=conf, category=category,
        title="t", file=file, line=1, evidence=evidence,
        description="d", why_it_matters="w", recommendation="r", ai_fix_prompt="p",
    )


VULN_SRC = "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz"


def test_vendor_files_not_scanned():
    files = [
        _fs("node_modules/object-hash/index.js", "eval(" + VULN_SRC + ")"),
        _fs(".git/hooks/pre-commit", "eval(" + VULN_SRC + ")"),
        _fs("dist/bundle.min.js", "eval(" + VULN_SRC + ")"),
        _fs("src/app.js", "const sk = 'sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz';"),
    ]
    result = scan_root("proj", files)
    assert result.ignored_files == 3
    assert result.application_files == 1
    assert all(not f.file.startswith(("node_modules", ".git", "dist")) for f in result.findings)
    assert any(f.file == "src/app.js" for f in result.findings)


def test_duplicate_locations_grouped():
    files = [
        _fs("src/a.js", "eval(req.body.x)"),
        _fs("src/b.js", "eval(req.query.y)"),
        _fs("src/c.js", "eval(data.z)"),
    ]
    result = scan_root("proj", files)
    eval_groups = [g for g in result.groups if g["rule_id"] == "CODE-001"]
    assert eval_groups
    assert len(eval_groups[0]["locations"]) >= 2


def test_low_confidence_deprioritized():
    fs_ = [
        _fs("src/config.py", "yaml.load(open('f').read(), Loader=yaml.Loader)"),
        _fs("src/app.js", "const sk = 'sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz';"),
    ]
    result = scan_root("proj", fs_)
    for g in result.groups:
        if g["confidence"] == "low":
            assert g["priority"] == "P3"
        if g["rule_id"] == "SECRET-001":
            assert g["priority"] == "P0"


def test_group_penalty_once():
    f1 = _finding("X-001", Severity.CRITICAL, Confidence.HIGH, "a.py")
    f2 = _finding("X-001", Severity.CRITICAL, Confidence.HIGH, "b.py")
    f3 = _finding("X-001", Severity.CRITICAL, Confidence.HIGH, "c.py")
    from scanner.scoring import compute_score
    score, _ = compute_score([f1, f2, f3])
    assert score == 80


def test_group_findings_locations():
    f1 = _finding("X-001", Severity.CRITICAL, Confidence.HIGH, "a.py")
    f2 = _finding("X-001", Severity.CRITICAL, Confidence.HIGH, "b.py")
    groups = group_findings([f1, f2])
    assert len(groups) == 1
    assert len(groups[0]["locations"]) == 2


def test_report_data_contract():
    files = [
        _fs("src/a.js", "const x = eval(req.body);"),
        _fs("src/b.js", "const sk = 'sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz';"),
    ]
    result = scan_root("proj", files)
    d = result.to_dict()
    for g in d["groups"]:
        assert "beginner" in g
        assert g["beginner"]["title"]
        assert g["beginner"]["summary"]
        assert g["beginner"]["why_it_matters"]
        assert g["beginner"]["recommended_action"]
        assert "technical" in g
        assert g["technical"]["rule_id"] == g["rule_id"]
        assert g["technical"]["name"] == g["title"]
        assert g["locations"]
        assert g["ai_fix_prompt"]
