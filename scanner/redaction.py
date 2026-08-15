from __future__ import annotations

import re

REDACT = "<redacted>"

SECRET_PREFIXES = re.compile(
    r"(?i)(sk_live_|sk_live|sk_|pk_live_|sk-ant-|sk-proj-|ghp_|gho_|ghs_|xoxb|AKIA|AIza|eyJ)[A-Za-z0-9_\-\.]{6,}"
)
URL_CREDS = re.compile(r"(://[^:/@\s]+:)[^@\s]{1,60}(@)")


def mask_secret(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return REDACT
    return v[:4] + "*" * min(12, len(v) - 4)


def redact_evidence(snippet: str, max_len: int = 200) -> str:
    def _mask(m: re.Match) -> str:
        return mask_secret(m.group(0))

    out = SECRET_PREFIXES.sub(_mask, snippet)
    out = URL_CREDS.sub(r"\1****\2", out)
    return out[:max_len]
