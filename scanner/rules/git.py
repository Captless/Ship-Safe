from scanner.rules.base import Rule, Severity, Confidence

RULES: list[Rule] = [
    Rule(
        rule_id="GIT-001",
        title=".env file committed to repository",
        category="git",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="A .env file containing environment variables was found in the repository. Environment files routinely hold API keys, database passwords, and other live secrets.",
        why_it_matters="A committed .env file exposes every secret the application runs on. Even if it is deleted in a later commit, it remains recoverable in git history and on any clone, fork, or mirror made while it existed.",
        recommendation="Remove the file and purge it from git history, rotate every secret it contained, and ensure .env is listed in .gitignore before the next commit.",
        ai_fix_prompt="Inspect the .env file to catalog every secret it defines. Do not print the values. Use git filter-repo or equivalent history rewriting to remove the file from all commits, then force-push only after confirming with the team since history rewriting affects every collaborator. Delete the file from the working tree if it is not needed locally, and confirm `.env` plus variants such as `.env.*` and `!.env.example` are in .gitignore. Rotate each exposed secret on its provider. Preserve any behavior that depends on the values by leaving the developer's local environment intact. Verify with a fresh clone that no .env appears in history. Summarize the rotation checklist.",
        technical="files_include matches paths containing .env, so the rule fires on .env and its production/local variants. The match callable returns a hit when the file content contains `=`, indicating real variable assignments rather than an empty template.",
        beginner="A .env file is where passwords for your app are stored. If it is uploaded to the repository, anyone with access to the code can read all your passwords.",
        files_include=[".env"],
        match=lambda content, extra: [(1, ".env file present")] if "=" in content else [],
    ),
    Rule(
        rule_id="GIT-002",
        title=".gitignore does not protect .env files",
        category="git",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="The repository's .gitignore does not reference .env, so environment files can be committed by mistake.",
        why_it_matters="Without an ignore entry, a future `git add -A` or careless `git add .env` silently stages secrets. This rule fires only when the ignore file lacks the safeguard, so it is a warning rather than proof of an actual leak.",
        recommendation="Add entries such as `.env`, `.env.*`, `!.env.example`, and keep the ignore file in place so secrets never reach staging.",
        ai_fix_prompt="Inspect the .gitignore file and the repository layout. Add ignore rules for `.env`, `.env.*` (or `.env.[a-z]*`), and an exception `!.env.example` if an example template exists. Preserve all existing ignore rules. Check for related secrets like key files and private-key patterns, and add `*.pem`/`*.key` entries if any exist. Update or add tests that assert the ignore file contains the .env rules. Run any repo hygiene check available. Summarize the added patterns and note that existing committed .env files still need removal from history.",
        technical="files_include restricts scanning to .gitignore. The match callable returns a hit only when the file content does not contain `.env`, i.e. the ignore rules are missing the safeguard.",
        beginner="A .gitignore file is a 'do not upload' list. If .env is not on that list, your passwords can end up on the internet by accident.",
        files_include=[".gitignore"],
        match=lambda content, extra: (
            [(1, ".gitignore does not ignore .env")]
            if ".env" not in content
            else []
        ),
    ),
    Rule(
        rule_id="GIT-003",
        title="npm registry auth token in .npmrc",
        category="git",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="The .npmrc file contains registry authentication material, typically a token for a private package registry.",
        why_it_matters="Committing .npmrc with a token lets anyone with repo access publish to or pull from private npm packages under the owner's identity. The token can be copied and reused until revoked.",
        recommendation="Remove the token from .npmrc, rotate it in the registry, and load it from an environment variable or machine-local user configuration instead of committing it.",
        ai_fix_prompt="Inspect the .npmrc file and identify the authentication lines. Replace the literal token with an environment-variable reference such as `//registry.npmjs.org/:_authToken=${NPM_TOKEN}` or the project's existing secret-loading pattern. Confirm the token is not embedded elsewhere in the repo. Preserve the registry endpoints, scopes, and other settings so installs keep working. Add or update tests that verify npm commands resolve the token from the environment. Run the build or install pipeline and confirm authentication still works with a test token. Summarize the changed file and the registry-side token rotation step.",
        technical="Pattern matches `_authToken`, password-style lines scoped to a registry host, or any line combining a registry with a token. Medium confidence because the matched text could be a placeholder.",
        beginner="An npm token is a password for downloading private code packages. If it is in a file you upload to the repository, strangers can use it to install from your private registries.",
        files_include=[".npmrc"],
        patterns=[r"_authToken|//.*:_password|registry.*token"],
    ),
]
