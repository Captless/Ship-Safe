from scanner.rules.base import Rule, Severity, Confidence


def _match_deploy_005(content: str, extra: str) -> list[tuple[int, str]]:
    if '"scripts"' not in content and "'scripts'" not in content:
        return []
    if '"dev"' not in content and "'dev'" not in content:
        return []
    for token in ('"start"', "'start'", '"build"', "'build'", '"prestart"', '"poststart"'):
        if token in content:
            return []
    return [(1, "no production start script")]


RULES: list[Rule] = [
    Rule(
        rule_id="DEPLOY-001",
        title="Localhost reference in production config",
        category="deployment",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="A localhost, 127.0.0.1, or 0.0.0.0 address appears in a deployment configuration such as docker-compose, .env.production, nginx, .env.example, vercel.json, or netlify.toml.",
        why_it_matters="Production deployments that bind to or connect to loopback addresses fail to reach real services, or expose services in ways not intended for production. Localhost service bindings are also a common source of hard-to-diagnose routing bugs.",
        recommendation="Point production configs at real hostnames and external addresses. Use environment-specific values rather than shipping a local template into deployment.",
        ai_fix_prompt="Inspect the deployment configuration files in this project (docker-compose, .env.production, nginx configs, .env.example, vercel.json, netlify.toml). Find localhost, 127.0.0.1, or 0.0.0.0 references that would be wrong in production and replace them with the intended production addresses or environment-variable placeholders. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests asserting production configs avoid loopback addresses, verify the fix by running the relevant checks, and summarize the changes.",
        technical="0.0.0.0 as a bind address listens on all interfaces, which may expose a service publicly when intended for internal use. localhost/127.0.0.1 as a connect target cannot reach services running in other hosts or containers.",
        beginner="These files tell your app where to find things when it is live. Localhost addresses point back at the machine itself, which usually does not work in the cloud. Update them to the real addresses.",
        files_include=["docker-compose", ".env.production", "nginx", ".env.example", "vercel.json", "netlify.toml"],
        patterns=[r'(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0)'],
    ),
    Rule(
        rule_id="DEPLOY-003",
        title="Unvalidated environment variable access",
        category="deployment",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="Code accesses environment variables directly via os.environ[...] without a default or validation. Missing required variables will crash at runtime, and unvalidated values are passed straight into the application.",
        why_it_matters="A typo, missing secret, or wrong value in deployment config surfaces as a runtime crash, or worse, as an unvalidated value (like an empty secret) being silently accepted. Fail-fast, validated config makes deployment mistakes visible immediately.",
        recommendation="Read environment variables through a validation layer (pydantic-settings, environs, or a config module) that requires and type-checks every variable at startup.",
        ai_fix_prompt="Inspect the configuration loading code in this project. Find direct os.environ[...] accesses and replace them with validated reads that fail fast when required variables are missing and provide typed defaults where appropriate. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests covering missing and invalid environment variables, verify the fix by running the relevant checks, and summarize the changes.",
        technical="os.environ['KEY'] raises KeyError when absent, surfacing as a confusing mid-startup crash. os.environ.get returns None silently, which can feed a missing secret into the app. Centralized validation with explicit required/optional and type coercion avoids both failure modes.",
        beginner="The app reads its settings from environment variables. If one is missing or wrong, checking them all at startup with clear errors saves you from strange crashes later.",
        files_include=["config.py", "settings.py", "main.py"],
        patterns=[r'(?i)(os\.environ\s*\[\s*["\'][^"\']+["\']\s*\])'],
    ),
    Rule(
        rule_id="DEPLOY-004",
        title="Debug mode enabled in deployment",
        category="deployment",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Debug mode is enabled in a deployment context via debug=True/true/1, NODE_ENV=development, or FLASK_DEBUG=1/True/true. Deployed applications must not run in debug mode.",
        why_it_matters="Debug mode ships interactive debuggers, full stack traces, and development-only routes to production visitors. It can even grant code execution via the Werkzeug console, making a single request enough to compromise the host.",
        recommendation="Set debug=false, NODE_ENV=production, and FLASK_DEBUG=0 for all deployed environments. Verify in CI that deployment configs never enable debug.",
        ai_fix_prompt="Inspect the deployment configuration and scripts for this project. Find debug=true/true/1, NODE_ENV=development, or FLASK_DEBUG=1/True/true settings and change them so deployed environments run in production mode. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests asserting production deployment configs disable debug, verify the fix by running the relevant checks, and summarize the changes.",
        technical="Flask's debug mode and Werkzeug's debugger allow arbitrary Python code execution from the browser. Node.js development mode disables optimizations, enables verbose errors, and can expose source maps and dev-only routes.",
        beginner="Debug mode gives running code superpowers for development but is dangerous in public. It can even let someone run code on your server through the browser. Keep it off when the app goes live.",
        patterns=[r'(?i)(debug\s*=\s*(True|true|1)|NODE_ENV\s*=\s*["\']development["\']|FLASK_DEBUG\s*=\s*(1|True|true))'],
    ),
    Rule(
        rule_id="DEPLOY-005",
        title="No production start script",
        category="deployment",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="package.json defines a dev script but no production start or build script. Deployments will default to the development server, which is unsuitable and unsafe for production traffic.",
        why_it_matters="Without an explicit production start script, deployment platforms may run 'npm start' (missing) or fall back to a dev server that is unoptimized, verbose, and slow. Production builds also skip minification and hardening steps.",
        recommendation="Add a start script that runs the production server (e.g. built assets or a proper web server entry point) and a build script if the app requires compilation.",
        ai_fix_prompt="Inspect package.json for this project. Confirm it has a dev script but no production start or build script. Add a start script that launches the production server and a build script if the app needs compilation, without touching other scripts or dependencies. Modify only the necessary files, avoid unrelated refactoring, preserve existing functionality, add or update tests asserting a production start script exists, verify the fix by running the relevant checks, and summarize the changes.",
        technical="Deployment platforms typically execute npm start (or the configured start command). Its absence causes the platform to pick a default, frequently the development server, which lacks production optimizations and exposes dev tooling.",
        beginner="The package.json is the app's instruction card for running. Right now it says how to run the development version but not the production version. Add the instruction that launches the real, public app.",
        files_include=["package.json"],
        match=_match_deploy_005,
    ),
]
