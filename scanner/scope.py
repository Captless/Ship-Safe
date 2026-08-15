from __future__ import annotations

from scanner.models import Severity, Confidence, Finding

EXCLUDED_DIRS = {
    "node_modules", "vendor", ".git", ".svn", ".hg", "dist", "build", "out",
    ".next", ".nuxt", ".cache", "coverage", "tmp", "temp", "target",
    "__pycache__", ".pytest_cache",
}

EXCLUDED_SUFFIXES = (".min.js", ".min.css", ".map")

APP_DIRS = {
    "src", "app", "pages", "components", "server", "api", "routes", "lib",
    "services", "functions", "backend", "frontend",
}

_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


def normalize_path(path: str) -> str:
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def is_ignored(path: str) -> bool:
    parts = [p for p in normalize_path(path).split("/") if p]
    if not parts:
        return True
    for part in parts:
        if part.lower() in EXCLUDED_DIRS:
            return True
    base = parts[-1].lower()
    return base.endswith(EXCLUDED_SUFFIXES)


def should_analyze(path: str) -> bool:
    return not is_ignored(path)


def priority_for(severity: Severity, confidence: Confidence) -> str:
    if severity == Severity.CRITICAL and confidence == Confidence.HIGH:
        return "P0"
    if severity == Severity.HIGH and confidence in (Confidence.HIGH, Confidence.MEDIUM):
        return "P1"
    if severity == Severity.MEDIUM:
        return "P2"
    return "P3"


def is_actionable(finding: Finding) -> bool:
    if finding.confidence == Confidence.HIGH:
        return True
    if finding.confidence == Confidence.MEDIUM and finding.evidence and finding.evidence.strip():
        return True
    return False


def severity_order(severity) -> int:
    return _ORDER.get(severity, 5)
