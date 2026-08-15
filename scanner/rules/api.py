from scanner.rules.base import Rule, Severity, Confidence

import re

_AUTH_HINTS = ("auth", "authorization", "token", "jwt", "session", "middleware", "bearer", "apikey")


def _api_007_match(content: str, extra: str) -> list[tuple[int, str]]:
    if any(h in content.lower() for h in _AUTH_HINTS):
        return []
    out = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        if "(" in line and "/api/" in line and re.search(
            r"['\"](get|post|put|delete|patch)['\"]|\.(get|post|put|delete|patch)\s*\(",
            line.lower(),
        ):
            out.append((line_no, line.strip()[:80]))
    return out

RULES: list[Rule] = [
    Rule(
        rule_id="API-100",
        title="HTTP routes or API endpoints detected",
        category="api",
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        description="HTTP route or API endpoint definitions were detected in the code.",
        why_it_matters="Presence of HTTP endpoints makes the API security checks relevant to this project.",
        recommendation="",
        ai_fix_prompt="",
        is_presence_signal=True,
        evidence_signal="HTTP route or API endpoint definitions found",
        patterns=[
            r"(?i)@app\.(route|get|post|put|delete|patch)",
            r"(?i)@router\.(get|post|put|delete|patch)",
            r"(?i)@(bp|blueprint)\.(route|get|post|put|delete|patch)",
            r"(?i)\b(app|router|express)\.(get|post|put|delete|patch)\s*\(",
        ],
    ),
    Rule(
        rule_id="API-001",
        title="Wildcard CORS on API server",
        category="api",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="The API server allows cross-origin requests from any origin via allow_origins=[\"*\"], origin=*, or 'Access-Control-Allow-Origin: *'. Any website can read API responses.",
        why_it_matters="A wildcard CORS header lets a malicious page in the victim's browser issue requests to your API and read the responses, including authenticated data. This turns any XSS or a malicious link into a data exfiltration channel.",
        recommendation="Set an explicit allowlist of trusted origins and keep credentials handling strict. If cookies or Authorization headers are used, the allowed origins must be exact domains.",
        ai_fix_prompt="Inspect the API server code for this project. Find wildcard CORS settings such as allow_origins=['*'], origin='*', or 'Access-Control-Allow-Origin: *'. Replace them with an explicit list of trusted client origins appropriate for this API. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests covering allowed and disallowed origins, verify the fix by running the relevant checks, and summarize the changes.",
        technical="'Access-Control-Allow-Origin: *' permits every origin to read responses. Combined with Allow-Credentials the browser blocks the combination, but a wildcard alone still permits cross-site reads of non-credentialed data and is almost never required in production.",
        beginner="It lets any website read your API's answers, so a fake page could pull user data through the browser. List only your real website domains instead of allowing everything.",
        patterns=[r'(?i)(allow_origins\s*=\s*\[\s*["\']\*\s*["\']\s*\]|origin\s*=\s*\*|Access-Control-Allow-Origin\s*:\s*\*)'],
    ),
    Rule(
        rule_id="API-002",
        title="Debug or status endpoint exposed without auth",
        category="api",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="A debug, status, health, metrics, or debug-flag route appears in the main server files or routes. Such endpoints frequently leak internals and are often left unprotected.",
        why_it_matters="Health and metrics endpoints can reveal framework versions, hostnames, and internal state. Debug endpoints can expose stack traces or interactive consoles that give attackers direct insight or even code execution.",
        recommendation="Remove debug endpoints in production, and protect status/metrics endpoints with authentication or restrict them to internal networks.",
        ai_fix_prompt="Inspect the server entry files and route definitions for this project. Identify exposed /debug, /status, /health, /metrics, /__debug__ routes or debug=True flags. Remove debug endpoints from production paths and add authentication or network restrictions to status and metrics endpoints. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests asserting these endpoints require auth or are absent in production, verify the fix by running the relevant checks, and summarize the changes.",
        technical="Debug tooling such as Flask's debug=True, Django's /__debug__ panel, or unauthenticated /metrics endpoints disclose versions, internal routes, and request detail. Metrics endpoints should sit behind auth or be served only on a private interface.",
        beginner="Debug and health endpoints are the app's vitals monitor. In production they should be private or switched off, otherwise strangers can read details meant only for your team.",
        files_include=["main.py", "app.py", "server.py", "routes"],
        patterns=[r'(?i)(/debug|/status|/health|/metrics|/__debug__|debug\s*=\s*True)'],
    ),
    Rule(
        rule_id="API-003",
        title="Admin route without auth guard",
        category="api",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="A route containing 'admin', 'internal', or 'manage' is declared with @app.get/@app.post/@app.route and has no visible authentication decorator guarding it.",
        why_it_matters="Admin and internal routes control sensitive operations. If reachable without authentication, any anonymous user can trigger privileged actions such as user management, data deletion, or configuration changes.",
        recommendation="Wrap privileged routes with an authentication and authorization guard, and verify the guard is enforced before any handler logic runs.",
        ai_fix_prompt="Inspect the route definitions in this project. Find routes whose paths contain admin, internal, or manage and check whether they are protected by an authentication decorator or middleware. Add the appropriate auth and role-based guard to any unprotected privileged route. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests asserting unauthenticated requests to these routes are rejected, verify the fix by running the relevant checks, and summarize the changes.",
        technical="A route like @app.get('/admin/users') without a login-required decorator accepts anonymous requests. The guard must run before handler code and ideally check the caller's role, not just the presence of a cookie.",
        beginner="An admin route is the app's control room. If there is no locked door (login check) on it, anyone can walk in and operate the controls. Add that login check.",
        patterns=[r'(?i)(@app\.(get|post|route)\("[^"]*(admin|internal|manage)[^"]*"\))'],
    ),
    Rule(
        rule_id="API-006",
        title="Secrets embedded in client API calls",
        category="api",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="A long API key, secret, token, or service_role value is embedded in client-side files such as JavaScript, TSX, HTML, or app config, where every visitor can read it.",
        why_it_matters="Client-side code is downloaded by every user, so embedded secrets are publicly readable and frequently remain in git history. A leaked service role key or API token gives attackers full access to the underlying service.",
        recommendation="Remove embedded secrets and route calls through a server-side proxy that injects credentials from environment variables or a secret manager. Rotate any leaked key immediately.",
        ai_fix_prompt="Inspect the client-side files of this project for embedded API keys, secrets, tokens, or service_role values. Remove them from client code and move the calls behind a server-side endpoint that uses environment-variable-supplied credentials. Rotate any leaked key and update the affected services. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests asserting no long secret-like strings appear in client files, verify the fix by running the relevant checks, and summarize the changes.",
        technical="Everything shipped to the browser is public. Patterns like apikey= or service_role= followed by a 20+ character string in .js/.tsx/.html files are credentials in cleartext. Supabase service_role and similar keys bypass row-level security and must never reach the client.",
        beginner="Anything in a webpage or app file can be read by anyone who visits. Putting the master key there is like taping the safe combination to the storefront window. Move it to your own server.",
        files_include=[".js", ".tsx", ".jsx", "index.html", "app.json"],
        patterns=[r'(?i)(apikey|api_key|secret|token|service_role|serviceRole)\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']'],
    ),
    Rule(
        rule_id="API-007",
        title="Sensitive endpoint without auth check",
        category="api",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        description="An /api/ route is declared with get/post/put/delete handlers in a way that does not obviously incorporate token or auth checks near the definition. Manual verification of the auth guard is required.",
        why_it_matters="API endpoints are the primary attack surface. A route that reads or mutates data without a working auth check exposes data and allows unauthorized writes.",
        recommendation="Review each flagged /api/ route and confirm an authentication and authorization check runs before the handler. Add guards where they are missing.",
        ai_fix_prompt="Inspect the API route definitions flagged in this project. For each /api/ route, verify whether an authentication or token check runs before the handler logic. Add the appropriate guard to any route that is missing one. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests asserting unauthenticated calls to these routes are rejected, verify the fix by running the relevant checks, and summarize the changes.",
        technical="This rule performs a lightweight pattern match on route declarations and cannot prove the absence of middleware-level auth. Follow up manually: check decorators, dependency-injected auth, and global middleware for each flagged route.",
        beginner="This is a reminder to double-check that your API routes have a login requirement. Some routes look protected but actually are not, so it is worth reviewing each one.",
        patterns=[],
        match=_api_007_match,
    ),
]
