# Ship Safe — Architecture Document

> Status: Draft · Version: 1.0 · Date: 2026-08-15
> Source of truth: `plan.md`

---

## 1. Architectural Principles

1. **Scanner engine is independent from the web application.**
2. The same scanner engine must eventually power:
   - Web SaaS
   - CLI
   - VS Code extension
   - CI/CD integration
3. **Do NOT tightly couple detection rules to HTTP routes or frontend code.**
4. Keep the scanner engine framework-independent where possible.
5. Prefer deterministic checks over LLM guesses.
6. No microservices. No Redis. No message queues. No Kubernetes — unless a concrete requirement appears.
7. Do not introduce unnecessary infrastructure or dependencies.

---

## 2. Conceptual Repository Structure

```
ship-safe/
├── scanner/                    # Core engine (framework-independent)
│   ├── core/                   # Engine, models, rule registry, orchestration
│   ├── rules/                  # Detection rule implementations
│   ├── analyzers/              # Framework-aware analyzers (Supabase, Stripe, etc.)
│   ├── models/                 # Data models (Finding, RuleResult, ScanResult)
│   ├── scoring/                # Ship Score calculation
│   └── reporting/              # Report generation, redaction
├── backend/                    # FastAPI web layer
│   ├── api/                    # HTTP routes
│   ├── services/               # Upload handling, scan orchestration, workspace mgmt
│   └── workers/                # Future background processing (not V1)
├── frontend/                   # Vanilla HTML/CSS/JS
│   ├── static/                 # Assets, styles, scripts
│   └── templates/              # Server-rendered pages (if any)
├── tests/                      # Unit, integration, fixtures
│   └── fixtures/               # Vulnerable + clean sample projects
├── docs/                       # This documentation set
├── Dockerfile
├── docker-compose.yml
└── README.md
```

> The exact structure may be refined during Phase 2 implementation if a better layout is justified.

---

## 3. Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Backend | Python 3 | Language of choice per plan |
| Backend framework | FastAPI | Typed, async-capable, auto OpenAPI docs |
| Frontend | Vanilla HTML + CSS + JS | No framework unless compelling reason appears |
| Database | PostgreSQL-compatible architecture | Supabase possible later; V1 minimizes DB dependence |
| Containerization | Docker | Portable, free-tier friendly |
| Local dev | Docker Compose | Reproducible setup |
| VCS | GitHub | — |

### Infrastructure Constraints

- **Avoid** microservices.
- **Avoid** Redis unless a concrete requirement appears.
- **Avoid** message queues unless a concrete requirement appears.
- **Avoid** Kubernetes.
- **Avoid** unnecessary dependencies.
- Deployment must remain portable between free/low-cost hosting providers.

---

## 4. Scanner Engine Design

### 4.1 Overview

A **rule-based static analysis engine**. Deterministic. No external AI APIs required.

### 4.2 Rule Schema

Each rule contains:

| Field | Purpose |
|-------|---------|
| `rule_id` | Stable identifier (e.g., `SECRET-001`) |
| `title` | Human-readable name |
| `category` | One of 10 detection categories |
| `severity` | critical / high / medium / low / informational |
| `confidence` | high / medium / low |
| `description` | What the rule detects |
| `detection logic` | The actual matcher/analyzer |
| `evidence` | Matched snippet (redacted) |
| `explanation` | Technical + beginner explanation |
| `recommendation` | Remediation guidance |
| `remediation guidance` | Detailed fix steps |
| `ai_fix_prompt` | Copyable prompt template for AI agents |

### 4.3 Finding Structure

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

### 4.4 Redaction

- Do **not** expose sensitive secret values in reports.
- Evidence is redacted where necessary.
- **Never print full secrets.**

### 4.5 Scan Processing Pipeline

```
1. Accept ZIP upload
2. Validate the upload
3. Extract safely
4. Detect project type/framework
5. Run relevant rules
6. Aggregate findings
7. Deduplicate findings
8. Calculate score
9. Produce structured JSON results
10. Render the report
```

Synchronous scanning for V1, designed so it can later be replaced with background processing. **No queue in V1.**

---

## 5. Framework Detection

Detect common project types **where practical**:

- Node.js
- React
- Next.js
- Vue
- Vite
- Express
- Python
- FastAPI
- Flask
- Django
- PHP
- Laravel

Also detect usage of:

- Supabase
- Firebase
- Prisma
- Stripe
- Common AI SDKs/providers

Framework detection **influences which rules are executed**.

> Do not pretend to understand frameworks that cannot be reliably detected.

---

## 6. Backend API Design

### 6.1 V1 Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness check |
| POST | `/api/scans` | Upload ZIP, start scan |
| GET | `/api/scans/{scan_id}` | Scan status/results |
| GET | `/api/scans/{scan_id}/report` | Full report |

### 6.2 Future Endpoints (NOT in V1)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/explain` | AI explanation |
| POST | `/api/github/connect` | GitHub integration |
| POST | `/api/auth` | Accounts |
| POST | `/api/billing` | Payments |

> Do not implement future endpoints until required.

---

## 7. Security of the Scanner Itself

### 7.1 Hard Rule: No Code Execution

Uploaded repositories are **untrusted**. **NEVER execute user application code.**

**NEVER:**
- run `npm install` on uploaded projects
- run `pip install` from uploaded projects
- run arbitrary build scripts
- run project startup commands
- execute package lifecycle scripts
- import arbitrary user Python modules
- execute uploaded binaries

**Static analysis only.**

### 7.2 Upload Safeguards

- ZIP path traversal protection
- ZIP bomb protection
- Extremely large file limits
- Excessive file count limits
- Recursive archive attack protection
- Symlink handling (where applicable)
- Scan timeouts
- Memory limits
- Temporary file cleanup

**Do not trust filenames or file extensions.**

### 7.3 Logging / Errors

- Do not log secrets.
- Do not expose raw uploaded source code in error messages.

---

## 8. Temporary File Lifecycle

```
Upload
→ temporary isolated workspace
→ scan
→ generate findings
→ delete uploaded source
```

- Do not persist source code unless explicitly required later.
- If persistent scan history is introduced later, store **metadata/results** rather than raw source by default.

---

## 9. AI Functionality (Optional, Secondary)

- The core scanner **must** work without external AI APIs.
- The core scanner **must not** require an LLM.
- If AI explanation is implemented, isolate it behind a **provider interface** so different providers can be supported later.
- Do **not** hardcode a specific paid AI provider into the scanner engine.

---

## 10. CLI Future

The scanner engine must eventually support:

```bash
ship-safe scan .
```

The CLI uses the **exact same rule engine**.

> Do not build the CLI during the initial MVP unless it requires minimal effort and does not slow down the web product.

---

## 11. Project Detection & Rule Activation Flow

```
Upload → Extract → Detect Project Type (manifests, config files)
     → Activate relevant rule sets per framework
     → Run generic rules + framework rules
     → Aggregate → Score → Report
```

Detection is manifest-based and file-pattern based (`package.json`, `pyproject.toml`, `requirements.txt`, `composer.json`, `*.env*`, etc.).

---

## 12. Related Documents

- [PRD.md](./PRD.md)
- [DETECTION-RULES.md](./DETECTION-RULES.md)
- [THREAT-MODEL.md](./THREAT-MODEL.md)
- [MVP-PLAN.md](./MVP-PLAN.md)
- [TEST-PLAN.md](./TEST-PLAN.md)
