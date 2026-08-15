from scanner.models import Finding, Severity, Confidence
from scanner.scoring import compute_score


def finding(sev, conf, rid="X-001"):
    return Finding(
        rule_id=rid, severity=sev, confidence=conf, category="test",
        title="t", file="f.py", line=1, evidence="e",
        description="d", why_it_matters="w", recommendation="r",
        ai_fix_prompt="p",
    )


def test_clean_score_is_100():
    assert compute_score([]) == (100, "LOOKING GOOD")


def test_critical_high_conf_penalty():
    score, grade = compute_score([finding(Severity.CRITICAL, Confidence.HIGH)])
    assert score == 80
    assert grade == "ALMOST READY"


def test_high_penalty():
    score, grade = compute_score([finding(Severity.HIGH, Confidence.HIGH)])
    assert score == 88
    assert grade == "ALMOST READY"


def test_medium_and_low():
    score, grade = compute_score(
        [finding(Severity.MEDIUM, Confidence.HIGH, "M-1"), finding(Severity.LOW, Confidence.HIGH, "L-1")]
    )
    assert score == 92
    assert grade == "LOOKING GOOD"


def test_low_confidence_softens_penalty():
    a = compute_score([finding(Severity.CRITICAL, Confidence.HIGH)])
    b = compute_score([finding(Severity.CRITICAL, Confidence.LOW)])
    assert b[0] > a[0]


def test_info_flood_does_not_tank_score():
    infos = [finding(Severity.INFO, Confidence.HIGH) for _ in range(50)]
    assert compute_score(infos)[0] == 100


def test_many_criticals_floor_at_zero():
    crits = [finding(Severity.CRITICAL, Confidence.HIGH, f"C-{i}") for i in range(10)]
    assert compute_score(crits)[0] == 0


def test_duplicate_rule_and_file_deduped():
    f = finding(Severity.CRITICAL, Confidence.HIGH)
    score, _ = compute_score([f, f])
    assert score == 80
