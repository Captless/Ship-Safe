from tests.conftest import FIXTURES, read_fixture_tree
from scanner.engine import scan_root


def test_engine_detects_vulnerabilities(vuln_project):
    result = scan_root("vuln", vuln_project)
    rids = {f.rule_id for f in result.findings}
    assert result.project_type in ("node", "python", "unknown")
    assert result.score < 100
    assert "SECRET-001" in rids or "SECRET-006" in rids
    assert any(f.category == "dangerous-code" for f in result.findings)


def test_engine_clean_low_fp(clean_project):
    result = scan_root("clean", clean_project)
    sev = {f.severity.value for f in result.findings}
    assert "critical" not in sev
    assert "high" not in sev
    assert len(result.findings) <= 2


def test_engine_redacts_secrets(vuln_project):
    result = scan_root("vuln", vuln_project)
    for f in result.findings:
        assert "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz" not in f.evidence
        assert "s3cr3t" not in f.evidence


def test_engine_reports_frameworks(vuln_project):
    result = scan_root("vuln", vuln_project)
    assert "nodejs" in result.frameworks or "python" in result.frameworks
