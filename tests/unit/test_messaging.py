from scanner.messaging import beginner_for, SEVERITY_LABELS


def test_severity_labels_are_text():
    assert SEVERITY_LABELS["critical"] == "Fix this first"
    assert SEVERITY_LABELS["high"] == "Important"
    assert SEVERITY_LABELS["medium"] == "Review this"
    assert SEVERITY_LABELS["low"] == "Good to know"
    assert SEVERITY_LABELS["informational"] == "Optional"


def test_rule_override_copy():
    b = beginner_for("CODE-005", "dangerous-code", "Path traversal", "d", "w", "r")
    assert b["title"] == "Your app may be exposing files"
    assert "paths" in b["recommended_action"]
    assert b["why_it_matters"]
    assert b["summary"]
    assert b["technical_name"] == "Path traversal"


def test_category_fallback_copy():
    b = beginner_for("UNKNOWN-1", "secrets", "Tech title", "d", "w", "r")
    assert b["title"] == "A sensitive credential may be visible in your app"
    assert b["technical_name"] == "Tech title"


def test_unknown_fallback():
    b = beginner_for("X-9", "no-such-category", "T", "d", "w", "r")
    assert b["title"]
    assert b["summary"]
    assert b["why_it_matters"]
    assert b["recommended_action"]
