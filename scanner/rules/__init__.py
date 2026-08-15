from scanner.rules.base import Rule, Severity, Confidence  # noqa: F401
from scanner.rules import secrets, git, config, api, deploy, database, auth, payments, code, dependencies


def all_rules() -> list[Rule]:
    out: list[Rule] = []
    for mod in (secrets, git, config, api, deploy, database, auth, payments, code, dependencies):
        out.extend(getattr(mod, "RULES", []))
    return out
