from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EvidenceState(str, Enum):
    NOT_OBSERVED = "not_observed"
    OBSERVED = "observed"
    CHECKED_CLEAN = "checked_clean"
    LIMITED = "limited"
    NEEDS_REVIEW = "needs_review"


@dataclass
class CategoryEvidence:
    state: EvidenceState
    signals: list[str] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    checks_passed: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    confidence: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "signals": self.signals,
            "checks_run": self.checks_run,
            "checks_passed": self.checks_passed,
            "findings": self.findings,
            "confidence": self.confidence,
        }


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    confidence: Confidence
    category: str
    title: str
    file: str
    line: int | None
    evidence: str
    description: str
    why_it_matters: str
    recommendation: str
    ai_fix_prompt: str
    technical: str = ""
    beginner: str = ""
    priority: str = "P3"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "description": self.description,
            "why_it_matters": self.why_it_matters,
            "recommendation": self.recommendation,
            "ai_fix_prompt": self.ai_fix_prompt,
            "technical": self.technical,
            "beginner": self.beginner,
            "priority": self.priority,
        }


@dataclass
class FileSnapshot:
    path: str
    content: str
    binary: bool = False


@dataclass
class ScanTarget:
    root: str
    files: list[FileSnapshot] = field(default_factory=list)
    project_type: str = "unknown"
    frameworks: set[str] = field(default_factory=set)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    groups: list[dict] = field(default_factory=list)
    project_type: str = "unknown"
    frameworks: list[str] = field(default_factory=list)
    files_scanned: int = 0
    application_files: int = 0
    ignored_files: int = 0
    duration_ms: int = 0
    score: int = 100
    grade: str = "Good"
    summary: dict[str, Any] = field(default_factory=dict)
    passed: list[str] = field(default_factory=list)
    evidence: dict[str, CategoryEvidence] = field(default_factory=dict)
    readiness: str = ""
    readiness_details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "project_type": self.project_type,
            "frameworks": sorted(self.frameworks),
            "files_scanned": self.files_scanned,
            "application_files": self.application_files,
            "ignored_files": self.ignored_files,
            "duration_ms": self.duration_ms,
            "findings": [f.to_dict() for f in self.findings],
            "groups": self.groups,
            "summary": self.summary,
            "passed": self.passed,
            "evidence": {cat: ev.to_dict() for cat, ev in sorted(self.evidence.items())},
            "readiness": self.readiness,
            "readiness_details": self.readiness_details,
        }
