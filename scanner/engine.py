from __future__ import annotations

import time

from scanner.models import ScanResult, ScanTarget
from scanner.detection import detect_scan_target
from scanner.rules import all_rules
from scanner.scoring import compute_score
from scanner.redaction import redact_evidence
from scanner.scope import should_analyze, priority_for, is_actionable, severity_order
from scanner import messaging

MAX_FINDINGS_PER_RULE_PER_FILE = 5


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


def scan_root(root: str, files) -> ScanResult:
    t0 = time.perf_counter()
    app_files = [f for f in files if should_analyze(f.path)]
    target = detect_scan_target(root, app_files)
    rules = [r for r in all_rules() if r.applies_to(target)]
    findings = []
    passed: set[str] = set()
    for rule in rules:
        hit_files = []
        for f in app_files:
            if rule.files_include and not any(x in f.path for x in rule.files_include):
                continue
            if rule.files_exclude and any(x in f.path for x in rule.files_exclude):
                continue
            if f.binary:
                continue
            hits = rule.find_in(f.content)
            if hits:
                for line, ev in hits[:MAX_FINDINGS_PER_RULE_PER_FILE]:
                    finding = rule.make_finding(
                        target, f.path, line, redact_evidence(ev)
                    )
                    finding.priority = priority_for(finding.severity, finding.confidence)
                    findings.append(finding)
                hit_files.append(f.path)
        if not hit_files:
            passed.add(rule.rule_id)
    score, grade = compute_score(findings)
    grouped = group_findings(findings)
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
            "rules_ran": len(rules),
            "rules_passed": len(passed),
            "total_findings": len(findings),
            "actionable_findings": sum(1 for f in findings if is_actionable(f)),
            "observations": sum(1 for f in findings if not is_actionable(f)),
        },
        passed=sorted(passed),
    )
