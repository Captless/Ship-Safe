from scanner.rules.base import Rule, Severity, Confidence


def _manifest_detected(content: str, extra: str) -> list[tuple[int, str]]:
    if content.strip():
        return [(1, "dependency manifest detected")]
    return []


def _dependency_manifest_detected(content: str, extra: str) -> list[tuple[int, str]]:
    return _manifest_detected(content, extra)


RULES: list[Rule] = [
    Rule(
        rule_id="DEP-001",
        title="Dependency manifest detected",
        category="dependencies",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        description="Potential issue detected: a dependency manifest file is present in the project.",
        why_it_matters="Dependency manifests define the libraries your project relies on. Tracking them (and their lockfiles) keeps builds reproducible and audits achievable.",
        recommendation="Keep the manifest and commit a lockfile so all environments install identical dependency versions.",
        ai_fix_prompt="Confirm the flagged manifest is the project's real dependency file. If a lockfile is missing, generate and commit one (e.g. npm install --package-lock-only, pip freeze, or the language's native lock command). Do not modify unrelated files, and verify the project still installs and tests pass. Summarize the changes.",
        technical="package.json, requirements.txt, pyproject.toml, Pipfile, and composer.json declare project dependencies. Their presence enables supply-chain review and pinned builds.",
        beginner="This file lists the external libraries the project uses. Committing it, plus its lockfile, means every install gets the exact same versions.",
        files_include=[
            "package.json",
            "requirements.txt",
            "pyproject.toml",
            "Pipfile",
            "composer.json",
        ],
        match=_dependency_manifest_detected,
    ),
    Rule(
        rule_id="DEP-002",
        title="Unpinned dependency ranges",
        category="dependencies",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        description="Potential issue detected: package.json declares dependencies with version ranges (~ or ^) instead of exact pins.",
        why_it_matters="Range-based versions resolve to different packages over time, so installs are not reproducible and updates can silently break the build.",
        recommendation="Pin exact versions (remove ^/~) and commit the lockfile so dependency resolution is deterministic.",
        ai_fix_prompt="Inspect the flagged package.json dependencies. Replace range prefixes (^, ~) with exact pinned versions and regenerate the lockfile. Modify only the dependency declarations needed, avoid unrelated changes, and run the test suite to confirm nothing breaks. Verify the fix, then summarize the changes.",
        technical="The pattern \"dependencies\"[^}]{0,400}?\"[^\"]+\":\\s*\"[~^] detects caret (^) and tilde (~) range prefixes in dependency declarations, which allow floating minor or patch versions.",
        beginner="The ^ and ~ signs in front of version numbers mean 'a slightly newer version is fine'. That can change behavior without warning. Pinning exact versions keeps everything stable.",
        files_include=["package.json"],
        patterns=[r"\"(dependencies|devDependencies)\"[^}]{0,400}?\"[^\"]+\":\s*\"[~^]"],
    ),
    Rule(
        rule_id="DEP-003",
        title="Suspicious package name (possible typosquat)",
        category="dependencies",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        description="Potential issue detected: package.json contains a package name that resembles a known typosquatting pattern.",
        why_it_matters="Typosquatted packages are named to imitate popular libraries and are often published with malicious code. Installing them can compromise the whole project.",
        recommendation="Verify each flagged package against the official registry and maintainer. If the name is a typo of a well-known package, install the correct one.",
        ai_fix_prompt="Inspect the flagged package names in package.json. Compare each against the legitimate package registry and the project's imports to confirm intent. If any name is a typo of a trusted library, correct the dependency and its imports, then run the tests. Do not change unrelated dependencies, and summarize the changes.",
        technical="The pattern looks for names that mimic popular packages, such as reactt, reacct, expressjs, xss-, yarn-, npms-, lodash., or uuidv. These resemble common lookalike typosquats found in supply-chain attacks.",
        beginner="Some attackers publish packages whose names are one letter off from popular ones, hoping developers install the fake by mistake. Always double-check package names are exactly right.",
        files_include=["package.json"],
        patterns=[
            r"(?i)\"[^\" ]*(reactt|reacct|expressjs|xss-|yarn-|npms-|lodash\.|uuidv)[^\" ]*\"",
        ],
    ),
]
