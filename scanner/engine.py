from __future__ import annotations

import time
from typing import Any, Callable

from scanner.models import (
    ScanResult,
    ScanTarget,
    EvidenceState,
    CategoryEvidence,
    Finding,
    Severity,
    Confidence,
)
from scanner.detection import detect_scan_target
from scanner.rules import all_rules
from scanner.scoring import compute_score, derive_readiness
from scanner.redaction import redact_evidence
from scanner.scope import should_analyze, priority_for, is_actionable, severity_order
from scanner import messaging

MAX_FINDINGS_PER_RULE_PER_FILE = 5

ProgressReporter = Callable[[dict[str, Any]], None] | None


EVIDENCE_CATEGORIES = {"payments", "auth", "database", "api", "deployment"}


def group_findings(findings) -> list[dict]:
    groups: dict[tuple[str, str], dict] = {}
    for f in findings:
        key = (f.rule_id, f.category)
        if key not in groups:
            groups[key] = {
                "rule_id": f.rule_id,
                "category": f.category,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "priority": f.priority,
                "description": f.description,
                "why_it_matters": f.why_it_matters,
                "recommendation": f.recommendation,
                "ai_fix_prompt": f.ai_fix_prompt,
                "locations": [],
            }
        groups[key]["locations"].append({
            "file": f.file,
            "line": f.line,
            "evidence": f.evidence,
        })
    for g in groups.values():
        g["beginner"] = messaging.beginner_for(
            g["rule_id"], g["category"], g["title"],
            g["description"], g["why_it_matters"], g["recommendation"],
        )
        g["technical"] = {
            "name": g["title"],
            "rule_id": g["rule_id"],
            "confidence": g["confidence"],
            "severity": g["severity"],
        }
    out = list(groups.values())
    out.sort(key=lambda g: (severity_order(g["severity"]), -len(g["locations"])))
    return out


def _report(reporter: ProgressReporter, **kwargs: Any) -> None:
    if reporter is not None:
        reporter(kwargs)


def scan_root(root: str, files, progress: ProgressReporter = None) -> ScanResult:
    t0 = time.perf_counter()
    app_files = [f for f in files if should_analyze(f.path)]
    _report(
        progress,
        phase="filtering",
        files_discovered=len(files),
        files_skipped=len(files) - len(app_files),
        files_to_scan=len(app_files),
    )
    target = detect_scan_target(root, app_files)
    all_rules_list = [r for r in all_rules() if r.applies_to(target)]

    presence_rules = [r for r in all_rules_list if r.is_presence_signal]
    check_rules = [r for r in all_rules_list if not r.is_presence_signal]

    presence_by_cat: dict[str, list] = {}
    for r in presence_rules:
        presence_by_cat.setdefault(r.category, []).append(r)

    check_by_cat: dict[str, list] = {}
    for r in check_rules:
        check_by_cat.setdefault(r.category, []).append(r)

    findings = []
    rule_hits: dict[str, bool] = {}
    checks_scanned: dict[str, set[str]] = {cat: set() for cat in check_by_cat}

    total = len(app_files)
    for idx, f in enumerate(app_files):
        _report(
            progress,
            phase="scanning",
            current=idx + 1,
            total=total,
            current_file=f.path,
            files_analyzed=idx + 1,
            findings_found=len(findings),
        )
        if f.binary:
            continue
        for rule in presence_rules:
            if not rule.should_scan_file(f.path):
                continue
            hits = rule.find_in(f.content)
            if hits:
                rule_hits[rule.rule_id] = True
        for rule in check_rules:
            if not rule.should_scan_file(f.path):
                continue
            checks_scanned[rule.category].add(rule.rule_id)
            hits = rule.find_in(f.content)
            if hits:
                rule_hits[rule.rule_id] = True
                for line, ev in hits[:MAX_FINDINGS_PER_RULE_PER_FILE]:
                    finding = rule.make_finding(
                        target, f.path, line, redact_evidence(ev)
                    )
                    finding.priority = priority_for(finding.severity, finding.confidence)
                    findings.append(finding)

    _report(progress, phase="reviewing")

    score, grade = compute_score(findings)
    grouped = group_findings(findings)

    evidence: dict[str, CategoryEvidence] = {}
    all_evidence_cats = EVIDENCE_CATEGORIES & set(presence_by_cat.keys())
    for cat in all_evidence_cats:
        presence_rules_cat = presence_by_cat.get(cat, [])
        check_rules_cat = check_by_cat.get(cat, [])

        signals = [r.evidence_signal for r in presence_rules_cat if r.rule_id in rule_hits]

        findings_for_cat = [f for f in findings if f.category == cat]
        finding_rule_ids = sorted(set(f.rule_id for f in findings_for_cat))

        checks_ran = sorted(checks_scanned.get(cat, set()))
        checks_passed = [rid for rid in checks_ran if rid not in rule_hits]

        if findings_for_cat:
            state = EvidenceState.NEEDS_REVIEW
        elif not signals:
            state = EvidenceState.NOT_OBSERVED
        elif not checks_ran:
            state = EvidenceState.OBSERVED
        elif len(checks_ran) < len([r for r in check_rules_cat if r.applies_to(target)]):
            state = EvidenceState.LIMITED
        else:
            state = EvidenceState.CHECKED_CLEAN

        presence_confidences = [r.confidence for r in presence_rules_cat if r.rule_id in rule_hits]
        conf_str = "low"
        if presence_confidences:
            if any(c == Confidence.HIGH for c in presence_confidences):
                conf_str = "high"
            elif any(c == Confidence.MEDIUM for c in presence_confidences):
                conf_str = "medium"

        evidence[cat] = CategoryEvidence(
            state=state,
            signals=signals,
            checks_run=checks_ran,
            checks_passed=checks_passed,
            findings=finding_rule_ids,
            confidence=conf_str,
        )

    excluded_cats = {cat for cat, ev in evidence.items() if ev.state in (
        EvidenceState.NOT_OBSERVED, EvidenceState.OBSERVED, EvidenceState.LIMITED
    )}
    passed = {r.rule_id for r in all_rules_list if r.rule_id not in rule_hits and r.category not in excluded_cats}

    readiness, readiness_details = derive_readiness(score, evidence, findings)

    _report(
        progress,
        phase="building_report",
        current=total,
        total=total,
        files_analyzed=total,
        findings_found=len(findings),
    )
    dur = int((time.perf_counter() - t0) * 1000)
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    return ScanResult(
        findings=findings,
        groups=grouped,
        project_type=target.project_type,
        frameworks=sorted(target.frameworks),
        files_scanned=len(files),
        application_files=len(app_files),
        ignored_files=len(files) - len(app_files),
        duration_ms=dur,
        score=score,
        grade=grade,
        summary={
            "findings_by_severity": by_sev,
            "rules_ran": len(all_rules_list),
            "rules_passed": len(passed),
            "total_findings": len(findings),
            "actionable_findings": sum(1 for f in findings if is_actionable(f)),
            "observations": sum(1 for f in findings if not is_actionable(f)),
        },
        passed=sorted(passed),
        evidence=evidence,
        readiness=readiness,
        readiness_details=readiness_details,
    )