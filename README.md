# Ship Safe

> The pre-flight scanner for vibe-coded apps.

Scan your vibe-coded app before you deploy it. Upload a project ZIP and get a static security/config sanity check: Ship Score, structured findings, beginner-friendly explanations, and copyable AI fix prompts.

**Static analysis only. Uploaded source is never executed and is deleted after the scan.**

## Quick Start

### Local

```bash
python -m pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Open http://localhost:8000

### Docker

```bash
docker compose up --build
```

Open http://localhost:8000 · Health check: http://localhost:8000/health

## Tests

```bash
python -m pytest tests -q
```

Covers: rule unit tests (true positive / true negative / edge), scanner integration, ZIP safety (zip slip, bombs, symlinks, entry limits), scoring, API, and report rendering.

## How it works

1. `POST /api/scans` — upload ZIP
2. Safe extraction into an isolated temp workspace (path traversal / bombs / symlinks rejected, size & entry limits, cleanup guaranteed)
3. `scanner/` runs ~54 rules across 10 categories (secrets, git, config, database, auth, API, payments, dangerous code, dependencies, deployment) on detected frameworks
4. Findings deduplicated, secrets redacted, Ship Score computed (Critical -20 / High -12 / Medium -6 / Low -2, confidence-weighted, 0-100)
5. Report rendered (`GET /api/scans/{id}/report`) or returned as JSON

## Project layout

```
scanner/     # framework-independent engine (rules, engine, scoring, zip safety)
backend/     # FastAPI (health, scans, report) + static frontend
frontend/    # vanilla HTML/CSS/JS
tests/       # unit / integration / security + fixtures
docs/        # PRD, architecture, rules, threat model, plan, test plan
```

## Roadmap (not in V1)

CLI (`ship-safe scan .`), GitHub scanning, scan history, accounts, AI explanations (provider-isolated), billing.

## Docs

- [docs/PRD.md](docs/PRD.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/DETECTION-RULES.md](docs/DETECTION-RULES.md)
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
- [docs/MVP-PLAN.md](docs/MVP-PLAN.md)
- [docs/TEST-PLAN.md](docs/TEST-PLAN.md)
