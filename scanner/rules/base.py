from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from scanner.models import Finding, Severity, Confidence, ScanTarget


@dataclass
class Rule:
    rule_id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    description: str
    why_it_matters: str
    recommendation: str
    ai_fix_prompt: str
    technical: str = ""
    beginner: str = ""
    patterns: list[str] = field(default_factory=list)
    files_include: list[str] = field(default_factory=list)
    files_exclude: list[str] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    match: Callable[[str, str], list[tuple[int, str]]] | None = None
    is_presence_signal: bool = False
    evidence_signal: str = ""

    def __post_init__(self) -> None:
        self._compiled = [re.compile(p) for p in self.patterns]

    def applies_to(self, target: ScanTarget) -> bool:
        if not self.frameworks:
            return True
        return bool(target.frameworks & self.frameworks)

    def should_scan_file(self, path: str) -> bool:
        if self.files_exclude and any(x in path for x in self.files_exclude):
            return False
        if not self.files_include:
            return True
        return any(x in path for x in self.files_include)

    def find_in(self, content: str) -> list[tuple[int, str]]:
        if self.match:
            return self.match(content, "")
        hits: list[tuple[int, str]] = []
        for rx in self._compiled:
            for m in rx.finditer(content):
                line = content.count("\n", 0, m.start()) + 1
                hits.append((line, m.group(0)))
        return hits

    def make_finding(self, target: ScanTarget, file_path: str, line: int, evidence: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            confidence=self.confidence,
            category=self.category,
            title=self.title,
            file=file_path,
            line=line,
            evidence=evidence,
            description=self.description,
            why_it_matters=self.why_it_matters,
            recommendation=self.recommendation,
            ai_fix_prompt=self.ai_fix_prompt,
            technical=self.technical,
            beginner=self.beginner,
        )
