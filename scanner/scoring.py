from __future__ import annotations

from scanner.models import Severity, Confidence, Finding

PENALTIES = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 12,
    Severity.MEDIUM: 6,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

CONF_WEIGHT = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.75,
    Confidence.LOW: 0.5,
}

STATUS_RANGES = [
    (90, "LOOKING GOOD"),
    (75, "ALMOST READY"),
    (50, "REVIEW BEFORE SHIPPING"),
    (25, "DON'T SHIP YET"),
    (0, "HIGH RISK — FIX BEFORE SHIPPING"),
]


def status_for_score(score: int) -> str:
    for lo, label in STATUS_RANGES:
        if score >= lo:
            return label
    return STATUS_RANGES[-1][1]


def compute_score(findings: list[Finding]) -> tuple[int, str]:
    deduped: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.category)
        if key not in deduped:
            deduped[key] = f
    penalty = 0.0
    for f in deduped.values():
        penalty += PENALTIES.get(f.severity, 0) * CONF_WEIGHT.get(f.confidence, 0.5)
    penalty = min(penalty, 100)
    score = max(0, round(100 - penalty))
    return score, status_for_score(score)
