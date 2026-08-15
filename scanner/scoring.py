from __future__ import annotations

from typing import Any

from scanner.models import Severity, Confidence, Finding, EvidenceState, CategoryEvidence

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


READINESS_CRITICAL = "NOT READY TO SHIP"
READINESS_REVIEW = "REVIEW BEFORE SHIPPING"
READINESS_LIMITED = "LIMITED CONFIDENCE"
READINESS_READY = "LOOKS READY TO SHIP"


def derive_readiness(score: int, evidence: dict[str, CategoryEvidence], findings: list[Finding]) -> tuple[str, dict[str, Any]]:
    for f in findings:
        if f.severity == Severity.CRITICAL:
            return READINESS_CRITICAL, {"reason": "Critical security finding requires fixing before ship", "finding_ids": [f.rule_id]}
    for f in findings:
        if f.severity in (Severity.HIGH, Severity.MEDIUM):
            return READINESS_REVIEW, {"reason": "Important issues need review before shipping", "finding_ids": [f.rule_id]}

    limited_cats = [cat for cat, ev in evidence.items() if ev.state in (EvidenceState.OBSERVED, EvidenceState.LIMITED)]
    if limited_cats:
        return READINESS_LIMITED, {
            "reason": "Not enough coverage in some areas to give a confident readiness assessment",
            "limited_areas": limited_cats,
        }

    if score >= 90:
        return READINESS_READY, {"reason": "No issues found in checks performed"}
    return READINESS_REVIEW, {"reason": f"Score {score} below confident threshold for shipping"}
