from scanner.rules.base import Rule, Severity, Confidence

import re

_PLACEHOLDER_CREDENTIALS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "changeme",
    "change_me",
    "change-me",
    "your_password",
    "your-password",
    "yourpassword",
    "admin",
    "default",
    "example",
    "placeholder",
    "xxxx",
    "xxxxx",
    "xxx",
    "1234",
    "12345",
    "123456",
    "not_used",
    "redacted",
    "<secret>",
    "<password>",
    "enter_password",
}


def _match_conf_004(content: str, extra: str) -> list[tuple[int, str]]:
    rx = re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{1,40})["\']')
    hits: list[tuple[int, str]] = []
    for m in rx.finditer(content):
        value = m.group(2)
        if len(value) < 4:
            continue
        if value.lower() in _PLACEHOLDER_CREDENTIALS:
            continue
        if value.lower() in {"password", "passwd", "pwd"}:
            continue
        line = content.count("\n", 0, m.start()) + 1
        hits.append((line, m.group(0)))
    return hits


RULES: list[Rule] = [
    Rule(
        rule_id="CONF-001",
        title="Debug mode enabled in configuration",
        category="configuration",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Application configuration enables debug mode or uses the development environment. Flagged by debug/dev_mode/APP_ENV settings set to true or 'development'.",
        why_it_matters="Debug mode exposes verbose stack traces, internal routes, and detailed error pages to any visitor. This leaks source paths, dependency versions, and database or framework internals that help attackers map the application before crafting an exploit.",
        recommendation="Disable debug mode and set APP_ENV to a production value in all deployed environments. Enforce this in CI by failing builds that ship debug=true.",
        ai_fix_prompt="Inspect the configuration files for this project. Identify where debug mode is enabled or APP_ENV is set to 'development'. Change the setting so debug is off and the environment is production-safe for deployed builds, while preserving the ability to run debug locally via a different config or environment variable. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests that assert the production config keeps debug disabled, verify the fix by running the relevant checks, and summarize the changes.",
        technical="Any flag such as DEBUG=true, DEV_MODE=true, APP_ENV=development, or Flask's debug=True enables interactive debuggers and full exception tracebacks. In frameworks like Django this also enables the DEBUG tool and serves static media. Set DEBUG=false and APP_ENV=production in deployable configs.",
        beginner="Debug mode is like leaving the doors open with the blueprint showing. It shows internal error details to visitors that should never see them. Turn it off for the real, public version of your app and keep it on only when developing on your own computer.",
        patterns=[r'(?i)(debug|dev_mode|APP_ENV)\s*[:=]\s*(true|"development"|\'development\'|development)'],
    ),
    Rule(
        rule_id="CONF-002",
        title="Wildcard CORS configuration",
        category="configuration",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="CORS is configured to allow requests from any origin. Flagged by allow_origins/cors_origins/origin/Access-Control-Allow-Origin set to the wildcard '*'.",
        why_it_matters="A wildcard CORS policy lets any website read responses from your API. An attacker can host a page that makes authenticated requests to your backend from a victim's browser and exfiltrate the responses, bypassing same-origin policy protections.",
        recommendation="Replace '*' with an explicit allowlist of trusted origins. When credentials (cookies, Authorization headers) are used, you must list specific origins because browsers refuse to send credentials with a wildcard policy.",
        ai_fix_prompt="Inspect the configuration files for this project and find where CORS origins are set to the wildcard '*'. Replace it with an explicit allowlist of the exact domains that legitimately call this service, using the framework's supported syntax. Keep any wildcard only if the service serves no credentials and the API is intended to be fully public, and document that decision. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests covering allowed and disallowed origins, verify the fix by running the relevant checks, and summarize the changes.",
        technical="CORS headers with 'Access-Control-Allow-Origin: *' disable the same-origin policy for reading responses. If the server reflects credentials (cookies, Authorization), 'Allow-Credentials: true' combined with '*' is rejected by browsers, but with no credentials a wildcard still allows cross-site reads of public-but-sensitive data.",
        beginner="Wildcard CORS means 'any website may read this API's answers'. A malicious site could trick a logged-in user into leaking data through their own browser. Only allow the sites you actually control.",
        patterns=[r'(?i)(allow_origins|cors_origins|origin\s*:\s*|Access-Control-Allow-Origin)\s*[:=\[\("]?\s*\[?[\'"]?\s*\*'],
    ),
    Rule(
        rule_id="CONF-003",
        title="localhost reference in production configuration",
        category="configuration",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="A production or prod configuration section references localhost or 127.0.0.1, indicating the service is pointed at a local endpoint instead of a real production host.",
        why_it_matters="Services that connect to localhost in production fail at runtime or, worse, silently connect to a local instance that bypasses intended network controls and monitoring. It is a common symptom of copy-pasted local config being deployed.",
        recommendation="Verify the production configuration points every service URL, database host, and API endpoint at the intended production addresses. Remove or override localhost entries for deployed environments.",
        ai_fix_prompt="Inspect the configuration files for this project. Find production or prod sections that reference localhost or 127.0.0.1. Replace those references with the correct production hostnames, addresses, or environment-variable placeholders. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests asserting production configs contain no localhost references, verify the fix by running the relevant checks, and summarize the changes.",
        technical="A config like 'DATABASE_URL=postgres://user:pass@localhost:5432/db' under a [production] section connects the deployed app to the container's own port or a local database. This typically stems from shipping a developer .env into production.",
        beginner="Your app's production config is telling it to talk to 'my own computer' instead of the real servers. That usually means things break or connect to the wrong place once it is live. Update the addresses to the real ones.",
        patterns=[r'(?i)(production|prod)[^\n]{0,80}(localhost|127\.0\.0\.1)'],
    ),
    Rule(
        rule_id="CONF-004",
        title="Hardcoded credentials in configuration",
        category="configuration",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="A password, passwd, or pwd key is assigned a literal string value in a configuration file. Placeholder values such as 'password' or 'changeme' are excluded by the matching logic.",
        why_it_matters="Hardcoded passwords end up in version control history and are shared across every deployment, so a single leak compromises all environments. Real credentials should never live in source files.",
        recommendation="Move secrets to environment variables or a secret manager (AWS Secrets Manager, HashiCorp Vault, etc.) and reference them from config. Rotate any credential that was committed, since git history never fully forgets.",
        ai_fix_prompt="Inspect the configuration files for this project. Find hardcoded password or credential strings and replace them with references to environment variables or the project's secret-management mechanism. Note that placeholder values like 'password' or 'changeme' are excluded, so focus on real-looking values. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests or config validation that catch hardcoded credentials, verify the fix by running the relevant checks, and summarize the changes.",
        technical="Literal credentials in config files are visible in every branch, tag, and CI log. Even when the value is later removed, the secret remains recoverable from git history. Use os.getenv or a secrets library instead.",
        beginner="Writing the real password in a file is like writing the key code on the front door. Anyone who sees the file, now or later, has access. Store passwords somewhere secret and only load them when the app starts.",
        patterns=[r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{1,40}["\']'],
        match=_match_conf_004,
    ),
    Rule(
        rule_id="CONF-005",
        title="Verbose error reporting enabled",
        category="configuration",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="Verbose error reporting is enabled in configuration, including debug=True, error_reporting(E_ALL), show_error_details, or detail=True. Such settings expose internals when an error occurs.",
        why_it_matters="Verbose error output includes stack traces, query strings, and file paths that reveal the technology stack and internal structure. Attackers use this information to choose targeted exploits instead of guessing blindly.",
        recommendation="Use terse, generic error pages in production and log full details server-side only. Map error_reporting and detail flags to a production-safe level.",
        ai_fix_prompt="Inspect the configuration files for this project. Find verbose error reporting settings such as debug=True, error_reporting(E_ALL), show_error_details, or detail=True. Change them so production builds return generic error responses while full details are still logged server-side. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests asserting production error responses are generic, verify the fix by running the relevant checks, and summarize the changes.",
        technical="PHP error_reporting(E_ALL) with display_errors on, or frameworks with detail=True, render internal exception data to the client. Store the full traceback in logs instead and return an opaque message to the user.",
        beginner="When the app breaks, verbose errors print the app's guts on screen, and those details help attackers. Let the app's diary (logs) keep the details private and show visitors only a polite 'something went wrong'.",
        patterns=[r'(?i)(debug\s*=\s*True|error_reporting\(E_ALL\)|show_error_details|detail\s*=\s*True)'],
    ),
    Rule(
        rule_id="CONF-006",
        title="Insecure or missing secret key",
        category="configuration",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="A SECRET_KEY is set to an empty, short, or placeholder value in settings.py or config.py, meaning session and signature protections rely on a weak or default secret.",
        why_it_matters="The secret key signs cookies, CSRF tokens, and tokens. A short or default key lets an attacker forge signed data, hijack sessions, or tamper with tokens.",
        recommendation="Set SECRET_KEY to a long random value (at least 32 bytes) loaded from an environment variable or secret manager. Rotate it immediately if a weak value was ever deployed.",
        ai_fix_prompt="Inspect the configuration files for this project. Find the SECRET_KEY assignment in settings.py or config.py and replace any empty, short, or placeholder value with a reference to an environment variable or secret manager that supplies a long random key at runtime. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests asserting the secret key is long and not a placeholder, verify the fix by running the relevant checks, and summarize the changes.",
        technical="Django, Flask, and similar frameworks use SECRET_KEY to sign session cookies and tokens. A value of 15 characters or fewer is brute-forceable; the flag pattern covers empty, short, and obvious placeholder strings.",
        beginner="The secret key is the app's master password for signing things like login cookies. If it is short or left as a default, attackers can guess it and forge access. Use a long, random key kept out of the code.",
        files_include=["settings.py", "config.py"],
        patterns=[r'SECRET_KEY\s*=\s*["\'][^"\']{0,15}["\']'],
    ),
]
