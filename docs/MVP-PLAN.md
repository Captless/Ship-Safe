# Ship Safe — MVP Implementation Plan

> Status: Draft · Version: 1.0 · Date: 2026-08-15
> Source of truth: `plan.md`

---

## 1. Scope

Build the **smallest real product first**: a web app where a user uploads a project ZIP, receives a static security/compliance scan, sees a Ship Score with structured findings, and can copy AI fix prompts and download a report.

**Out of scope for V1:**
- Billing/payments
- Accounts/auth
- CLI
- GitHub scanning
- Scan history
- AI explanations (isolated behind interface only)
- Background job queue

---

## 2. Milestones Overview

| Phase | Name | Deliverable |
|-------|------|-------------|
| 1 | Plan | Architecture, docs, constraints (this set) |
| 2 | Core scanner | Engine, models, rules, scoring, tests |
| 3 | Security | Safe ZIP extraction, limits, workspace |
| 4 | API | Minimal FastAPI endpoints |
| 5 | Frontend | Upload → progress → results |
| 6 | Integration testing | Full flow verified |
| 7 | Hardening | Security, FP review, perf, logging |
| 8 | Deployment | Docker, prod config, health checks |
| 9 | Final review | Clean-environment deploy verification |

---

## 3. Phase Detail

### PHASE 1 — PLAN ✅ (current)

- Inspect repository / existing files / constraints. *(complete)*
- Produce architecture. *(docs/ARCHITECTURE.md)*
- Identify dependencies.
- Define milestones, tests, risks.
- **Do not start coding yet.**

### PHASE 2 — IMPLEMENT CORE (scanner/)

**Deliverables:**
- Data models: `Finding`, `RuleResult`, `ScanResult`, `Rule`
- Rule registry: discover + register rules
- Scanner engine: orchestrates project detection → rule execution → aggregation → dedup
- Scoring module: severity penalties, confidence weighting, normalization to 0–100
- Framework/project detection module
- Redaction utilities
- Reporting module (JSON structure)
- **Unit tests for rules** (TP/TN/edge), scoring tests, integration tests

**Decisions to lock in this phase:**
- Rule format: Python classes vs YAML/JSON declarative — pick simplest that stays extensible
- Matcher strategy: regex-based first, AST-aware (tree-sitter) only where high value
- Finding schema finalized (see DETECTION-RULES.md)

### PHASE 3 — IMPLEMENT SECURITY

**Deliverables:**
- Safe ZIP extraction (see THREAT-MODEL.md §3.1–3.6)
- Limits: upload size, uncompressed size, per-file size, entry count, compression ratio
- Temporary workspace management + guaranteed cleanup
- Input validation at API boundary
- Scan + per-rule timeouts
- Symlink/archive recursion defenses
- **ZIP safety tests**

### PHASE 4 — IMPLEMENT API (backend/)

**Deliverables:**
- `GET /health`
- `POST /api/scans` — accept ZIP, validate, extract, scan
- `GET /api/scans/{scan_id}` — status/results
- `GET /api/scans/{scan_id}/report` — full report
- Structured error responses
- Structured logging (no secrets)
- **API tests**

### PHASE 5 — IMPLEMENT FRONTEND (frontend/)

**Deliverables:**
- Landing page: positioning, CTA "Scan My Project", supported tools list
- Upload UI: ZIP, static-analysis notice, limitations, data-handling note
- Progress indicator during scan
- Results page:
  1. Ship Score
  2. Critical findings
  3. Warnings
  4. Passed checks
  5. Categories
  6. Detailed findings (7 questions per finding)
- AI fix prompt copy button
- Report download/view
- Graceful error states
- Mobile-friendly + accessibility (keyboard, contrast, semantic HTML, focus states)
- Vanilla HTML/CSS/JS — no framework

### PHASE 6 — INTEGRATION TESTING

**Deliverables:**
- End-to-end: upload vulnerable fixture → scan → findings → score → report
- Clean fixture produces minimal findings (low false-positive rate)
- Malicious ZIP fixtures rejected safely
- Full test suite green

### PHASE 7 — HARDENING

**Review and tighten:**
- Security (THREAT-MODEL.md matrix)
- False-positive audit against fixtures
- Error handling paths
- Performance (large projects, timeouts)
- Temp cleanup verification
- Logging (no secrets)
- Edge cases: empty ZIP, non-ZIP file, binary project, huge file

### PHASE 8 — DEPLOYMENT

**Deliverables:**
- Dockerfile (multi-stage: build → runtime)
- docker-compose.yml for local dev + prod portability
- Production environment configuration (env-var driven)
- Health check endpoint wired to container healthcheck
- Deployment documentation

### PHASE 9 — FINAL REVIEW

- Follow README from a clean environment; verify deployability
- Confirm all Definition of Done items (below)
- Documentation updated to match behavior

---

## 4. Milestones (Timeboxed Checkpoints)

| # | Gate | Exit Criteria |
|---|------|---------------|
| M1 | Core engine ready | Rules run on fixtures, findings produced, score computed, unit tests pass |
| M2 | Secure ingest ready | Malicious ZIPs rejected/contained; safety tests pass |
| M3 | API ready | All 4 endpoints work with correct errors; API tests pass |
| M4 | Frontend ready | Upload→results works; mobile + accessible |
| M5 | Integration green | Full flow + full test suite pass |
| M6 | Hardened | Security/FP/perf/logging reviewed and fixed |
| M7 | Deployable | Docker build + run from clean env; DoD complete |

---

## 5. Definition of Done

MVP complete only when a user can:

1. Open the web application.
2. Understand what the product does.
3. Upload a valid project ZIP.
4. Receive safe scan processing.
5. See a progress state.
6. Receive structured findings.
7. See a Ship Score.
8. Understand critical findings.
9. See affected files/locations.
10. Read beginner-friendly explanations.
11. Copy an AI fix prompt.
12. Download or view a report.
13. Encounter graceful errors for invalid uploads.
14. Be protected against malicious ZIP extraction.
15. Have uploaded source cleaned up after scanning.
16. Run the application locally using documented commands.
17. Build and run the application through Docker.
18. Run the complete automated test suite successfully.

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| False positives destroy trust | High | High-confidence rules first; TP/TN/edge tests per rule |
| Framework detection unreliable | Medium | Manifest-based detection; label uncertainty |
| Large repos time out | Medium | Limits + chunking + per-rule timeouts from day 1 |
| Score feels arbitrary | Medium | Transparent weights; show "why this score" in UI |
| ZIP/upload abuse | High | THREAT-MODEL mitigations in Phase 3 |
| Scope creep (AI, CLI, billing) | Medium | Explicit out-of-scope list; feature gate reviews |

---

## 7. Dependency List (Initial, keep minimal)

**Runtime (backend):**
- `fastapi`
- `uvicorn`
- `python-multipart` (file uploads)
- `pydantic` (comes with FastAPI)

**Testing:**
- `pytest`
- `httpx` (FastAPI TestClient)
- `python-magic` or content-sniffing alternative (optional, avoid if not needed)

**Infrastructure:**
- Docker, Docker Compose

> No Redis, no queue, no DB in V1 unless a concrete requirement appears.

---

## 8. Feature Gates (Do Not Implement Prematurely)

- ❌ Billing / monetization — until validated with real users
- ❌ Accounts / auth
- ❌ CLI (`ship-safe scan .`) — only if minimal effort, else V2
- ❌ GitHub repository scanning
- ❌ Scan history (store metadata/results, not source)
- ❌ AI explanations (provider interface may be scaffolded, not wired to paid APIs)
- ❌ Background processing queue

---

## 9. Related Documents

- [PRD.md](./PRD.md)
- [ARCHITECTURE.md](./ARCHITECTURE.md)
- [DETECTION-RULES.md](./DETECTION-RULES.md)
- [THREAT-MODEL.md](./THREAT-MODEL.md)
- [TEST-PLAN.md](./TEST-PLAN.md)
