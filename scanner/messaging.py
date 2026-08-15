from __future__ import annotations

from scanner.models import EvidenceState, CategoryEvidence

SEVERITY_LABELS = {
    "critical": "Fix this first",
    "high": "Important",
    "medium": "Review this",
    "low": "Good to know",
    "informational": "Optional",
}

_CATEGORY = {
    "secrets": (
        "A sensitive credential may be visible in your app",
        "A password, key, or token appears to be written directly in your code.",
        "Anyone who can see your code could copy it and use it with your account.",
        "Move it to an environment variable or a secret manager.",
    ),
    "dangerous-code": (
        "Your app may run untrusted code or access data in an unsafe way",
        "The app uses a low-level function that can become dangerous when it receives outside input.",
        "A user could potentially misuse this to run code or reach data they should not be able to.",
        "Replace the unsafe call with a safer, purpose-built function and validate any input.",
    ),
    "database": (
        "Your database queries may be unsafe",
        "Database commands appear to be built from text that may include outside input.",
        "A user could potentially change what a query does or reach data they should not see.",
        "Use parameterized queries or an ORM instead of building SQL from text.",
    ),
    "auth": (
        "Some parts of your app may not check who's signed in",
        "Some routes or functions do not appear to verify the user before running.",
        "Anyone could potentially reach these parts without proving who they are.",
        "Add a sign-in check and an authorization check to these routes.",
    ),
    "api": (
        "An API endpoint may trust client input too much",
        "A server endpoint appears to accept outside input without enough validation.",
        "A user could potentially use this to reach data or actions they should not.",
        "Validate and restrict what this endpoint accepts.",
    ),
    "config": (
        "A configuration setting may be unsafe",
        "A setting appears to be disabled or overly permissive.",
        "This could let a user bypass protections you thought were on.",
        "Review the setting and use the secure value.",
    ),
    "deploy": (
        "Your deployment setup may expose the app",
        "A deployment-related setting appears insecure.",
        "This could make the running app easier to attack.",
        "Review the deployment configuration and lock it down.",
    ),
    "git": (
        "Version-control files may leak information",
        "Something in repository metadata looks risky.",
        "Sensitive details could be recoverable by anyone with the repository.",
        "Remove the file and purge it from the repository history.",
    ),
    "payments": (
        "Payment handling may be insecure",
        "Payment-related code appears to handle sensitive card data unsafely.",
        "Card data could be exposed or charges could be misdirected.",
        "Follow the payment provider's secure integration guide.",
    ),
    "dependencies": (
        "A dependency may need attention",
        "A package or version constraint looks risky.",
        "Outdated or unexpected dependencies can carry known problems.",
        "Review the dependency and update to a supported version.",
    ),
}

_RULES = {
    "CODE-005": (
        "Your app may be exposing files",
        "The app builds file paths using values that may come from outside the application.",
        "Someone could potentially use this to access files that were not meant to be public.",
        "Review the file path handling and make sure user-controlled paths cannot escape the intended folder.",
    ),
    "CODE-008": (
        "User content may be able to run code",
        "The app inserts content into a page in a way that may let it run as code.",
        "A visitor could potentially make code run in another visitor's browser.",
        "Escape or sanitize content before inserting it into the page.",
    ),
    "CODE-001": (
        "Your app may execute code from text",
        "The app uses eval() on a string, which runs whatever is in the text.",
        "If outside input reaches it, a user could potentially run code on your server.",
        "Replace eval() with a safer way to handle the data.",
    ),
    "CODE-003": (
        "A shell command may be built from unsafe text",
        "The app builds a command for the operating system from text that may include outside input.",
        "A user could potentially add their own commands.",
        "Do not build commands from text; pass arguments separately and validate them.",
    ),
    "CODE-004": (
        "Your database query may be unsafe",
        "The app builds a database query by gluing text together.",
        "A user could potentially change what the query does or reach data they should not see.",
        "Use parameterized queries or an ORM instead of building SQL from text.",
    ),
    "CODE-009": (
        "Your app may load untrusted data in an unsafe way",
        "The app loads data with a function that can run code when reading it.",
        "A crafted file or message could potentially run code on your server.",
        "Use the safe loading mode or only load data you trust.",
    ),
    "DB-001": (
        "A master database key may be visible in your app",
        "A service key that bypasses database protections appears in client code.",
        "Anyone who can see the app could use it to read or change all your data.",
        "Keep the key on the server and remove it from client code.",
    ),
    "DB-005": (
        "Your database password may be visible",
        "A database address with a password inside appears in your code.",
        "Anyone who can see the code could connect to your database.",
        "Remove the password from the string and load it from an environment variable.",
    ),
    "SECRET-002": (
        "A private key may be committed to your project",
        "A private key file appears inside the project.",
        "Anyone with the project could copy the key and use it as you.",
        "Remove the key, rotate it, and keep it out of version control.",
    ),
}

_FALLBACK = (
    "Something here deserves attention",
    "The scanner found a potential issue in this area.",
    "It may be worth reviewing before you launch.",
    "Open the technical details and review the flagged code.",
)


def _pick(rule_id: str, category: str):
    if rule_id in _RULES:
        return _RULES[rule_id]
    return _CATEGORY.get(category, _FALLBACK)


def beginner_for(rule_id: str, category: str, title: str, description: str,
                 why_it_matters: str, recommendation: str) -> dict:
    btitle, summary, why, action = _pick(rule_id, category)
    return {
        "title": btitle,
        "summary": summary,
        "why_it_matters": why,
        "recommended_action": action,
        "technical_name": title or rule_id,
        "technical_description": description or "",
        "technical_why": why_it_matters or "",
        "technical_recommendation": recommendation or "",
    }


EVIDENCE_AREA_LABELS = {
    "payments": "Payment handling",
    "auth": "Authentication",
    "database": "Database",
    "api": "API & endpoints",
    "deployment": "Deployment",
    "secrets": "Secrets",
    "git": "Git & source control",
    "configuration": "Configuration",
    "dangerous-code": "Code safety",
    "dependencies": "Dependencies",
}


EVIDENCE_MESSAGES = {
    EvidenceState.NOT_OBSERVED: {
        "summary": "No evidence found for {area}.",
        "why_it_matters": "Ship Safe did not find sufficient evidence that this area exists in your project. This does not mean it is absent — just that it could not be assessed.",
        "recommended_action": "No action needed.",
    },
    EvidenceState.OBSERVED: {
        "summary": "{area} was detected, but specific security checks for it were not performed.",
        "why_it_matters": "Code related to {area} was found, but Ship Safe did not run targeted security checks for this area.",
        "recommended_action": "Consider adding security controls for {area}.",
    },
    EvidenceState.CHECKED_CLEAN: {
        "summary": "No issues found in the checks performed for {area}.",
        "why_it_matters": "The checks that ran found no issues. This does not guarantee that {area} is secure — only that the checks performed passed.",
        "recommended_action": "No action needed.",
    },
    EvidenceState.LIMITED: {
        "summary": "Partial assessment of {area}.",
        "why_it_matters": "Ship Safe attempted to assess {area} but could not establish complete coverage. Some checks ran, others did not apply or could not run.",
        "recommended_action": "Review {area} manually for additional security controls.",
    },
    EvidenceState.NEEDS_REVIEW: {
        "summary": "Issues found in {area} that need review.",
        "why_it_matters": "Security findings were detected in {area} that require your attention before shipping.",
        "recommended_action": "Review the findings above and fix the issues before launching.",
    },
}


def evidence_for(category: str, ev: CategoryEvidence) -> dict[str, str]:
    area = EVIDENCE_AREA_LABELS.get(category, category)
    messages = EVIDENCE_MESSAGES.get(ev.state, EVIDENCE_MESSAGES[EvidenceState.NOT_OBSERVED])
    return {
        "state": ev.state.value,
        "area": area,
        "summary": messages["summary"].format(area=area),
        "why_it_matters": messages["why_it_matters"].format(area=area),
        "recommended_action": messages["recommended_action"].format(area=area),
        "signals": ev.signals,
        "checks_run": ev.checks_run,
        "checks_passed": ev.checks_passed,
        "findings": ev.findings,
        "confidence": ev.confidence,
    }
