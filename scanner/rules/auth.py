from scanner.rules.base import Rule, Severity, Confidence

_FIX_PROMPT = (
    "Inspect the flagged route file(s) and the app's authentication setup. Explain the proposed fix. "
    "Modify only the necessary files, avoid unrelated refactoring, and preserve existing functionality. "
    "Apply authentication/authorization consistently to every protected route without changing route behaviour. "
    "Add or update tests that prove the fix, verify the change, and summarize what was changed."
)

_AUTH_KEYWORDS = ("require_auth", "current_user", "getToken", "auth", "jwt", "session", "middleware")


def _check_route_auth(content: str, extra: str) -> list[tuple[int, str]]:
    has_routes = (
        "@app.route" in content
        or "@app.get" in content
        or "@app.post" in content
        or "@app.put" in content
        or "@app.delete" in content
        or "app.get(" in content
        or "app.post(" in content
        or "router.get(" in content
        or "router.post(" in content
    )
    if not has_routes:
        return []
    lowered = content.lower()
    if any(kw in lowered for kw in _AUTH_KEYWORDS):
        return []
    return [(1, "route definitions found; no auth middleware reference in file")]


RULES: list[Rule] = [
    Rule(
        rule_id="AUTH-100",
        title="Authentication flow detected",
        category="auth",
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        description="Authentication-related code (login, sign-in, registration, logout) was detected.",
        why_it_matters="Presence of authentication code makes the authentication security checks relevant to this project.",
        recommendation="",
        ai_fix_prompt="",
        is_presence_signal=True,
        evidence_signal="Authentication flow code found (login, sign-in, register)",
        patterns=[r"(?i)\b(login|signin|sign-in|signup|sign-up|register|logout|authenticate|authentication)\b"],
    ),
    Rule(
        rule_id="AUTH-101",
        title="Session or token handling detected",
        category="auth",
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        description="Session, token, or authorization handling was detected in the code.",
        why_it_matters="Presence of session or token handling makes the authorization security checks relevant to this project.",
        recommendation="",
        ai_fix_prompt="",
        is_presence_signal=True,
        evidence_signal="Session, token, or authorization handling found",
        patterns=[r"(?i)\b(jwt|bearer|session|cookie|csrf|oauth|oidc|token|isauthenticated|requireauth|authorization|middleware)\b"],
    ),
    Rule(
        rule_id="AUTH-001",
        title="API route with no obvious auth middleware",
        category="auth",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Potential issue detected: route definitions were found, but the file contains no reference to authentication middleware or token handling.",
        why_it_matters="API routes without authentication allow unauthenticated callers to invoke them. Sensitive endpoints may expose data or trigger actions without verification.",
        recommendation="Protect every endpoint that handles user data or privileged actions with authentication middleware and confirm access is denied by default.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="Routes expose HTTP handlers; without middleware that validates tokens and sets the current user, the handlers must re-validate identity themselves. Absence of auth keywords suggests endpoints are unguarded.",
        beginner="An endpoint with no login check is a door left open. Anyone can walk in and use it.",
        files_include=["main.py", "app.py", "server.js", "routes", "index.js", "app.ts"],
        match=_check_route_auth,
    ),
    Rule(
        rule_id="AUTH-002",
        title="Client-controlled authorization state",
        category="auth",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Potential issue detected: authorization state such as an isAdmin flag or role appears to be assigned from client-controlled input.",
        why_it_matters="If the client decides whether it is an admin, an attacker can flip the flag in the request and gain elevated privileges.",
        recommendation="Derive roles and privileges server-side from the verified session or token, never from request bodies, headers, or client-supplied values.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="Authorization must be computed on the server from an authenticated principal. Assigning roles from client-supplied data lets callers self-promote.",
        beginner="A user telling you they are an admin is not proof. The server must check who they actually are.",
        patterns=[r'(?i)(isAdmin|is_admin|isPremium|role)\s*[:=]\s*(true|1|"admin"|\'admin\'|isAdmin|props\.)'],
    ),
    Rule(
        rule_id="AUTH-005",
        title="JWT with alg none or hardcoded secret",
        category="auth",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        description="Potential issue detected: JWT verification uses the 'none' algorithm or a hardcoded short secret value.",
        why_it_matters="The 'none' algorithm lets attackers forge tokens without a signature, and a hardcoded secret is visible in source and trivially leaked.",
        recommendation="Require an asymmetric or strong symmetric algorithm, reject 'none', and load the signing secret from environment variables or a key manager.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="JWTs with alg:none pass signature checks that accept unsigned tokens. Short hardcoded secrets can also be brute-forced once the value is exposed in code.",
        beginner="The 'none' algorithm means 'no signature needed', so anyone can write their own login ticket. Secrets must stay out of the code.",
        patterns=[r'(?i)("alg"\s*:\s*"none"|algorithms?=\s*\[?\s*["\']none["\']|SECRET[_-]?KEY\s*=\s*["\'][^"\']{1,20}["\'])'],
    ),
    Rule(
        rule_id="AUTH-004",
        title="Token stored insecurely in localStorage",
        category="auth",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="Potential issue detected: an authentication token (JWT/session) is stored via localStorage.",
        why_it_matters="localStorage is readable by any script running on the page, so a single XSS bug exposes the token and hijacks the session.",
        recommendation="Keep tokens in memory where possible, or use a short-lived cookie with HttpOnly and Secure attributes. Never trust localStorage for auth secrets.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="localStorage has no origin-level script isolation; XSS can read it. HttpOnly cookies are inaccessible to JavaScript, limiting token exfiltration.",
        beginner="localStorage is a shared notepad every script on the page can read. Store login tokens somewhere scripts cannot touch.",
        patterns=[r'(?i)localStorage\.(setItem|getItem)\s*\(\s*[\'\"][^\'\"]*(token|jwt|session|auth)[^\'\"]*[\'\"]'],
    ),
    Rule(
        rule_id="AUTH-006",
        title="Missing resource-level authorization",
        category="auth",
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        description="Potential issue detected: a record is fetched by id without an obvious ownership check, which may allow IDOR (accessing other users' data).",
        why_it_matters="Fetching a record purely by id means any authenticated user can read or modify another user's resource just by changing the id.",
        recommendation="Verify the current user owns the resource, or that an explicit sharing policy allows access, before returning or mutating it.",
        ai_fix_prompt=_FIX_PROMPT,
        technical="IDOR happens when lookup filters only on the record key. A query scoped to the current user, e.g. where({ id, userId: currentUser.id }), closes the hole.",
        beginner="If the app fetches by an id you give it, try someone else's id — you may see their data. The app must check ownership first.",
        patterns=[r"(?i)(\.findOne\s*\(\s*\{[^}]*id|SELECT[^\n]*WHERE[^\n]*id\s*=\s*\$)"],
    ),
]
