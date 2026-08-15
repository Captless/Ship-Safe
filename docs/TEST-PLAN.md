# Ship Safe — Test Plan

> Status: Draft · Version: 1.0 · Date: 2026-08-15
> Source of truth: `plan.md`

---

## 1. Testing Strategy

Testing is **mandatory**. Every new detection rule must have tests. Tests verify behavior, not just that code runs.

### Test Layers

```
Unit tests (rules, scoring, redaction, zip-safety)
    └─ Scanner integration tests
         └─ API tests
              └─ Report rendering tests
                   └─ End-to-end flow (Phase 6)
```

---

## 2. Test Suites

### 2.1 Rule Unit Tests

For **every** rule, test:

| Case | Purpose |
|------|---------|
| **True positive** | Vulnerable code is flagged |
| **True negative** | Safe code is not flagged |
| **Edge case** | Boundaries: redaction, encoding, framework variations, empty files, case sensitivity |

Rules are categorized per [DETECTION-RULES.md](./DETECTION-RULES.md). Each rule file ships alongside a corresponding test module.

### 2.2 Scanner Integration Tests

- Full scan of a fixture project produces expected findings.
- Project/framework detection activates the correct rule sets.
- Findings aggregation and deduplication behave correctly.
- Scan results structure matches the finding schema.
- Secrets are redacted in all output.

### 2.3 ZIP Safety Tests

| Test | Verifies |
|------|----------|
| Zip Slip | `../` paths cannot escape workspace |
| Absolute path entries | Rejected |
| ZIP bomb | Aborted on size/ratio limit |
| Oversized file | Rejected/skipped with flag |
| Excessive entry count | Aborted with clear error |
| Symlink entries | Rejected or not followed |
| Recursive archives | Not extracted recursively |
| Malicious binary payload | Treated as data, never executed |
| Cleanup | Workspace removed after scan (success + error paths) |

### 2.4 Scoring Tests

- Severity penalties applied correctly (Critical -20, High -12, Medium -6, Low -2, Info 0).
- Normalization to 0–100.
- Confidence weighting.
- Deduplication of repeated findings.
- Informational flood does not tank the score.
- Score boundaries: 80–100, 60–79, 40–59, 0–39.

### 2.5 API Tests

- `GET /health` returns 200.
- `POST /api/scans` happy path returns scan result.
- Invalid uploads return graceful errors (not 500):
  - non-ZIP file
  - empty ZIP
  - oversized upload
  - malformed ZIP
- `GET /api/scans/{scan_id}` and `/report` return correct data/status.
- Error responses never leak raw source content.
- Response schema validated.

### 2.6 Report Rendering Tests

- Report includes: Ship Score, critical findings, warnings, passed checks, categories, detailed findings.
- Every finding answers the 7 questions (what/where/why/severity/confidence/action/AI prompt).
- Beginner + technical explanations present.
- AI fix prompt is copyable and follows the required structure.
- Report downloadable/views without backend dependency (static form).

---

## 3. Test Fixtures

### 3.1 Vulnerable Fixtures

Intentionally vulnerable sample projects, one per category focus:

| Fixture | Contains |
|---------|----------|
| `fixtures/vuln_secrets/` | Hardcoded API keys, `.env` committed, private keys |
| `fixtures/vuln_git/` | Tracked `.env`, missing `.gitignore` for secrets |
| `fixtures/vuln_config/` | `DEBUG=true`, wildcard CORS, localhost prod refs |
| `fixtures/vuln_db/` | Service-role key client-side, unsafe SQL concat, no RLS indicators |
| `fixtures/vuln_auth/` | Unprotected routes, client-controlled admin state, weak JWT |
| `fixtures/vuln_api/` | Wildcard CORS, debug endpoints, secrets in client calls |
| `fixtures/vuln_payments/` | Stripe secret exposed, webhook without signature check, client-controlled price |
| `fixtures/vuln_code/` | `eval`, shell exec with input, XSS via `innerHTML`, path traversal |
| `fixtures/vuln_deps/` | Manifests with suspicious/no-lockfile patterns |
| `fixtures/vuln_deploy/` | Localhost prod config, debug mode, missing health endpoint |

### 3.2 Clean Fixtures

- `fixtures/clean_node/` — Node.js project with no findings
- `fixtures/clean_python/` — Python/FastAPI project with no findings
- `fixtures/clean_mixed/` — Multi-framework, minimal findings

**Requirement:** Clean projects must not generate excessive false positives.

### 3.3 Malicious Fixtures

- `fixtures/malicious/zip_slip.zip` — path traversal entries
- `fixtures/malicious/zip_bomb.zip` — high compression ratio
- `fixtures/malicious/large_entries.zip` — excessive file count
- `fixtures/malicious/symlink.zip` — symlink entries
- `fixtures/malicious/nested.zip` — recursive archive
- `fixtures/malicious/binary_payload.zip` — executable-looking content (must never run)

---

## 4. Verification Checklist (from plan.md)

Tests must verify that:

- [ ] Expected issues are detected (vulnerable fixtures → findings)
- [ ] Clean projects do not generate excessive false positives
- [ ] Secrets are redacted
- [ ] Malicious ZIP paths cannot escape the workspace
- [ ] Scanner does not execute uploaded code
- [ ] Uploaded source is cleaned up after scanning
- [ ] Graceful errors for invalid uploads
- [ ] Scan timeouts enforced
- [ ] No secrets appear in logs

---

## 5. Quality Requirements to Assert in Tests

| Requirement | Test Coverage |
|-------------|---------------|
| Clear error handling | API error-path tests |
| Structured logging | Log assertions (secrets absent) |
| No secrets in logs | Log assertions |
| Input validation | Invalid upload tests |
| Upload size limits | Oversized upload tests |
| Scan timeout | Timeout test with slow fixture |
| Safe temp file handling | Cleanup tests |
| Health endpoint | `GET /health` test |
| Docker support | Container build/run (manual CI step) |
| Reproducible local setup | README-driven smoke test (Phase 9) |
| Automated tests | `pytest` suite green |
| Clean README | Manual review (Phase 9) |
| Env-var configuration | Config tests |
| No hardcoded credentials | Code review + secret scan of own repo |
| Graceful frontend errors | Frontend error-state tests |
| Mobile-friendly UI | Manual/responsive checks |

---

## 6. CI Considerations

Recommended CI (GitHub Actions) per phase:

| Stage | Job |
|-------|-----|
| Lint | `ruff` (Python), formatting checks |
| Unit | Rule tests, scoring tests, zip-safety tests |
| Integration | Scanner + API tests |
| Full | End-to-end flow against fixtures |
| Build | Docker build verification |

> Not strictly V1-required, but strongly recommended once repo is on GitHub.

---

## 7. Test Commands (Target)

```bash
# All tests
pytest

# Specific suite
pytest tests/rules/          # rule unit tests
pytest tests/security/       # zip-safety tests
pytest tests/scoring/        # scoring tests
pytest tests/api/            # API tests
pytest tests/reporting/      # report rendering tests
pytest tests/integration/    # scanner integration + e2e
```

---

## 8. Related Documents

- [DETECTION-RULES.md](./DETECTION-RULES.md)
- [THREAT-MODEL.md](./THREAT-MODEL.md)
- [MVP-PLAN.md](./MVP-PLAN.md)
- [ARCHITECTURE.md](./ARCHITECTURE.md)
