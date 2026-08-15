# Ship Safe — Detection Rules Specification

> Status: Draft · Version: 1.0 · Date: 2026-08-15
> Source of truth: `plan.md`

---

## 1. Rule Design

### 1.1 Rule Structure

Each rule has a consistent structure:

| Field | Description |
|-------|-------------|
| `rule_id` | Stable identifier, namespaced by category (e.g., `SECRET-001`) |
| `title` | Human-readable name |
| `category` | One of the 10 categories below |
| `severity` | `critical` / `high` / `medium` / `low` / `informational` |
| `confidence` | `high` / `medium` / `low` |
| `description` | What the rule detects |
| `detection logic` | The matcher / analyzer implementation |
| `evidence` | Matched snippet — **redacted** |
| `explanation` | Technical + beginner explanation |
| `recommendation` | What the user should do |
| `remediation guidance` | Detailed fix steps |
| `ai_fix_prompt` | Copyable prompt template for an AI coding agent |

### 1.2 Finding JSON

```json
{
    "rule_id": "SECRET-001",
    "severity": "critical",
    "confidence": "high",
    "category": "secrets",
    "title": "Potential hardcoded API credential",
    "file": "src/config/api.js",
    "line": 14,
    "evidence": "...",
    "description": "...",
    "why_it_matters": "...",
    "recommendation": "...",
    "ai_fix_prompt": "..."
}
```

### 1.3 Redaction Rules

- **Do not expose sensitive secret values in reports.**
- Evidence is redacted where necessary.
- Never print full secrets.
- Mask values (e.g., `sk_live_************`) while retaining enough context to locate the issue.

---

## 2. Detection Categories

### 2.1 SECRETS

**Target:** API keys, cloud credentials, private keys, database credentials, access tokens, AI provider keys, Stripe secret keys, suspicious credential patterns.

**Files to inspect:**
- `.env` files
- Committed environment files
- Configuration files
- Frontend source
- Git metadata where available

**Rules (V1 candidates):**

| Rule ID | Detection | Severity | Confidence |
|---------|-----------|----------|------------|
| `SECRET-001` | Hardcoded API credential pattern | critical | high |
| `SECRET-002` | Committed `.env` file | critical | high |
| `SECRET-003` | Private key file (`*.pem`, `*.key`, `id_rsa`, etc.) | critical | high |
| `SECRET-004` | AI provider API keys (OpenAI, Anthropic, etc.) | critical | high |
| `SECRET-005` | Stripe secret key (`sk_live_`) | critical | high |
| `SECRET-006` | Database connection string with credentials | critical | high |
| `SECRET-007` | AWS/cloud access key pattern (`AKIA...`) | critical | high |
| `SECRET-008` | Generic access/bearer token in source | high | medium |
| `SECRET-009` | Secret embedded in frontend/bundled JS | high | high |

**Never print full secrets.**

---

### 2.2 GIT

**Target:** Tracked `.env` files, obvious secret files, sensitive configuration committed to the repository, suspicious credential artifacts.

**Rule candidates:**

| Rule ID | Detection | Severity | Confidence |
|---------|-----------|----------|------------|
| `GIT-001` | `.env` file present in project (tracked or packaged) | critical | high |
| `GIT-002` | `.gitignore` missing or does not exclude `.env`/secrets | medium | medium |
| `GIT-003` | Credential artifacts present (`.npmrc` with token, `~/.aws`, etc.) | high | medium |
| `GIT-004` | Sensitive files committed without Git metadata available | informational | low |

**Constraint:** Do not modify the uploaded project.

---

### 2.3 CONFIGURATION

**Target:** `DEBUG=true`, development configuration, localhost production references, wildcard CORS, development/test credentials, verbose error configuration, unsafe production defaults.

**Rule candidates:**

| Rule ID | Detection | Severity | Confidence |
|---------|-----------|----------|------------|
| `CONF-001` | `DEBUG=true` / `APP_ENV=development` in production config | high | high |
| `CONF-002` | Wildcard CORS (`*`) in server config | high | high |
| `CONF-003` | `localhost`/`127.0.0.1` references in production config | medium | medium |
| `CONF-004` | Development/test credentials in config | high | medium |
| `CONF-005` | Verbose error reporting enabled in production | medium | medium |
| `CONF-006` | Unsafe production defaults (no secret key, permissive flags) | medium | medium |

---

### 2.4 DATABASE

**Focus:** Supabase, Firebase, PostgreSQL-related patterns, Prisma, SQL query patterns.

**Potential checks:**
- Missing RLS indicators
- Unsafe Supabase usage
- Service-role keys exposed client-side
- Suspicious database policies
- Unsafe query construction

**Rule candidates:**

| Rule ID | Detection | Severity | Confidence |
|---------|-----------|----------|------------|
| `DB-001` | Supabase service-role key in client-side code | critical | high |
| `DB-002` | Supabase usage without RLS indicators | high | medium |
| `DB-003` | Firebase config with admin/private key in client code | critical | high |
| `DB-004` | Unsafe SQL string concatenation | high | medium |
| `DB-005` | Raw DB connection string with hardcoded password | critical | high |
| `DB-006` | Prisma schema with broad/permissive access | medium | low |
| `DB-007` | Suspicious database policy pattern | medium | low |

> **Language constraint:** Use "Potential issue detected". Do not claim static analysis proves a database is secure or insecure.

---

### 2.5 AUTHENTICATION & AUTHORIZATION

**Target:** Unprotected API routes, missing obvious auth middleware, suspicious resource access patterns, client-controlled authorization state, insecure token handling indicators.

**Rule candidates:**

| Rule ID | Detection | Severity | Confidence |
|---------|-----------|----------|------------|
| `AUTH-001` | API route with no obvious auth middleware | high | medium |
| `AUTH-002` | Client-controlled authorization state (`isAdmin` from client) | high | medium |
| `AUTH-003` | Admin-only functionality reachable without auth check | high | low |
| `AUTH-004` | Token stored insecurely (localStorage for sensitive tokens) | medium | medium |
| `AUTH-005` | JWT with `alg: none` or hardcoded verification secret | critical | medium |
| `AUTH-006` | Missing resource-level authorization check indicators | high | low |

> Do not claim static analysis can completely verify authorization correctness. Use confidence levels.

---

### 2.6 API SECURITY

**Target:** Unauthenticated sensitive endpoints, dangerous admin endpoints, unrestricted methods, wildcard CORS, missing rate limiting indicators, exposed debug endpoints, client-side secrets.

**Rule candidates:**

| Rule ID | Detection | Severity | Confidence |
|---------|-----------|----------|------------|
| `API-001` | Wildcard CORS on API server | high | high |
| `API-002` | Debug/status endpoint exposed without auth | medium | medium |
| `API-003` | Admin route without auth guard | high | medium |
| `API-004` | Unrestricted HTTP methods (e.g., `app.all`, `@app.api_route` without methods) | medium | low |
| `API-005` | No rate-limiting indicators on auth endpoints | medium | low |
| `API-006` | Secrets embedded in client API calls | critical | high |
| `API-007` | Sensitive endpoint without authentication | high | medium |

---

### 2.7 PAYMENTS

**Focus:** Stripe.

**Checks:**
- Secret key exposure
- Suspicious webhook handling
- Missing obvious signature verification
- Client-controlled price
- Client-controlled subscription state

**Rule candidates:**

| Rule ID | Detection | Severity | Confidence |
|---------|-----------|----------|------------|
| `PAY-001` | Stripe secret key exposed | critical | high |
| `PAY-002` | Stripe webhook without signature verification | critical | high |
| `PAY-003` | Client-controlled price/amount in checkout | high | medium |
| `PAY-004` | Client-controlled subscription/plan state | high | medium |
| `PAY-005` | Stripe publishable key used where secret expected | medium | medium |

---

### 2.8 DANGEROUS CODE PATTERNS

**Target:** `eval`, unsafe shell execution, command injection patterns, unsafe SQL string construction, path traversal indicators, unsafe file handling, dangerous redirects, obvious XSS patterns.

**Rule candidates:**

| Rule ID | Detection | Severity | Confidence |
|---------|-----------|----------|------------|
| `CODE-001` | `eval()` usage | medium | high |
| `CODE-002` | Shell execution with user input (`os.system`, `child_process.exec`) | high | medium |
| `CODE-003` | Command injection pattern (user input into shell string) | critical | medium |
| `CODE-004` | SQL string concatenation with interpolation | high | medium |
| `CODE-005` | Path traversal indicators (`../` in file ops) | high | medium |
| `CODE-006` | Unsafe file handling (uploaded file used in filesystem paths) | high | medium |
| `CODE-007` | Dangerous redirects (open redirect via user input) | medium | medium |
| `CODE-008` | Obvious XSS pattern (`innerHTML` with unsanitized input, `dangerouslySetInnerHTML`) | high | medium |
| `CODE-009` | Unsafe deserialization (`pickle.loads`, `JSON.parse` of untrusted input) | high | low |

> Detection must favor **high-confidence findings** over aggressive false positives.

---

### 2.9 DEPENDENCIES

**Target:** Dependency manifests, package managers, suspicious/outdated dependency patterns.

**Rule candidates:**

| Rule ID | Detection | Severity | Confidence |
|---------|-----------|----------|------------|
| `DEP-001` | Dependency manifest detected (package.json, requirements.txt, etc.) | informational | high |
| `DEP-002` | Pin mismatch / no version lock (no lockfile committed) | informational | high |
| `DEP-003` | Suspicious package name patterns (typosquatting) | medium | low |
| `DEP-004` | Known-bad dependency pattern (if reliable local data available) | medium | low |

**Constraints:**
- Do **not** claim current vulnerability status unless vulnerability data is actually current.
- Do **not** build a fake vulnerability database.
- If a reliable local vulnerability database is unavailable, clearly label dependency checks as **limited**.

---

### 2.10 DEPLOYMENT READINESS

**Target:** Production configuration, environment variables, localhost references, debug configuration, missing obvious error handling, missing obvious health endpoint where applicable.

**Rule candidates:**

| Rule ID | Detection | Severity | Confidence |
|---------|-----------|----------|------------|
| `DEPLOY-001` | Localhost references in production config | medium | medium |
| `DEPLOY-002` | Missing health endpoint where applicable | low | low |
| `DEPLOY-003` | Missing env var handling / unvalidated required env vars | medium | medium |
| `DEPLOY-004` | Debug mode enabled | high | high |
| `DEPLOY-005` | No production start script / default dev server config | medium | medium |

---

## 3. Framework Detection & Rule Activation

Detected project types influence which rules run:

| Detected Framework | Activated Rule Sets |
|--------------------|--------------------|
| Node.js / Express | SECRET, GIT, CONF, API, CODE, DEP, DEPLOY |
| React / Next.js / Vue / Vite | SECRET, GIT, CONF, AUTH, API, CODE, DEP, DEPLOY |
| Python / FastAPI / Flask / Django | SECRET, GIT, CONF, DB, AUTH, API, CODE, DEP, DEPLOY |
| PHP / Laravel | SECRET, GIT, CONF, DB, AUTH, CODE, DEP, DEPLOY |
| Supabase usage | DB (+ SECRET for service-role keys) |
| Firebase usage | DB (+ SECRET for config keys) |
| Stripe usage | PAY (+ SECRET) |
| Prisma usage | DB |

---

## 4. False Positive Control

- False positives are a **major product risk**.
- Prioritize:
  - high confidence
  - useful evidence
  - actionable findings
- Every rule includes tests for:
  - **true positive** — correctly flagged vulnerable code
  - **true negative** — correctly ignores safe code
  - **edge case** — boundary conditions, redaction, framework variations
- Where confidence is uncertain, classify as a **warning** rather than critical.

---

## 5. Confidence & Language Guidelines

| Situation | Wording |
|-----------|---------|
| Static pattern matched, unambiguous | "Detected" |
| Pattern matched, context unclear | "Potential issue detected" |
| Framework-level claim without proof | "May indicate" |
| Authorization/database security claims | Always qualify — static analysis cannot prove security |

---

## 6. Related Documents

- [ARCHITECTURE.md](./ARCHITECTURE.md)
- [THREAT-MODEL.md](./THREAT-MODEL.md)
- [TEST-PLAN.md](./TEST-PLAN.md)
