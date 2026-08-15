## How to Use This Map

Use this document to identify the relevant architecture and narrow
codebase inspection.

Do not assume every detail is current.

For any implementation:

1. Read `AGENTS.md`.
2. Read this codemap.
3. Identify the relevant files from the map.
4. Inspect those actual files before planning.
5. Treat the current source code as the final authority.

Do not perform a full repository scan unless the requested change
requires cross-cutting architectural inspection or the codemap is
insufficient/outdated.

# Ship Safe — Codebase Map

## 1. Project Overview

Ship Safe is a web-based **pre-flight security scanner for "vibe-coded" apps**. Users upload a project ZIP; the backend extracts it into an isolated temp workspace, runs a deterministic regex-based static-analysis rule engine over the source (never executing it), computes a 0–100 Ship Score with a grade, and returns structured findings with beginner-friendly explanations and copyable AI fix prompts. No LLM runs during scanning. Uploads and workspaces are deleted after the scan.

## 2. Repository Structure

```
run.py                # dev entry: uvicorn backend.main:app (reload on :8000)
pyproject.toml        # project metadata, deps, dev console script (run:main)
requirements.txt      # pinned deps (fastapi, uvicorn, python-multipart, pytest, httpx)
Dockerfile            # python:3.12-slim, copies scanner/ backend/ frontend/, uvicorn cmd
docker-compose.yml    # single service, healthcheck hits /health
README.md             # quick start, tests, how-it-works, layout, roadmap
plan.md               # source-of-truth product plan (older than docs/)
backend/
  main.py             # FastAPI app: all routes, ScanState, report HTML renderer
scanner/
  engine.py           # scan_root orchestration + group_findings
  models.py           # Severity/Confidence enums, Finding, FileSnapshot, ScanTarget, ScanResult
  detection.py        # project-type + framework detection
  scope.py            # file include/exclude, priority, actionability, severity ordering
  scoring.py          # Ship Score + grade bands
  messaging.py        # beginner-friendly copy (per-rule / per-category / fallback)
  redaction.py        # secret masking in evidence
  ziputils.py         # safe ZIP extraction + text file iteration + cleanup
  rules/              # 10 rule modules, ~54 rules total; base.py defines Rule
frontend/             # vanilla HTML/CSS/JS (no build step)
  index.html          # SPA views: landing, upload, progress, complete, results
  app.js              # all client logic: upload, polling, progress UI, renderers
  styles.css          # dark GitHub-style theme, progress terminal UI, finding cards
tests/                # unit/ integration/ security/ + fixtures (vuln, clean)
docs/                 # PRD, ARCHITECTURE, DETECTION-RULES, THREAT-MODEL, MVP-PLAN,
                      # TEST-PLAN, plans/V1.1–V1.4 (this file lives here too)
```

## 3. Technology Stack

- **Backend**: Python ≥3.12, FastAPI 0.115.6, Uvicorn 0.34.0, python-multipart (form upload). Pure stdlib + FastAPI otherwise (threading, asyncio, tempfile).
- **Frontend**: Vanilla HTML/CSS/JS. No framework, no build system, no npm. Single `app.js`, `styles.css`, `index.html`.
- **Scanner**: Pure Python regex engine. No external scanning libraries.
- **Testing**: pytest 8.3.4, httpx (FastAPI TestClient), `python -m pytest tests -q`.
- **Deploy**: Docker / Docker Compose. No DB, no Redis, no queues.

## 4. Backend Architecture

**Main server entry point**

```
File: backend/main.py
Responsibility: FastAPI app; upload validation; async scan orchestration; progress state; report rendering; static frontend mount.
Important functions:
  create_scan()        # POST /api/scans — saves zip, starts _run_scan via asyncio.to_thread
  get_scan()           # GET /api/scans/{id} — running → {status,progress}; complete → {status,result}; else 404
  get_report()         # GET /api/scans/{id}/report — returns _render_report() HTMLResponse
  _run_scan()          # thread body: extract → discover → scan_root → store result → cleanup
  _report_progress()   # builds progress callback (phase-filtered) passed into scanner
  _report_discovery()  # progress callback for file discovery phase
  _render_report()     # standalone HTML report (score banner, top-5 cards, observations)
  _prune_storage()     # TTL (3600s) cleanup of _storage/_active dicts
```

**State model** — `ScanState` (in `backend/main.py`) holds `status`, `phase`, `message`, counters (`current`, `total`, `current_file`, `files_discovered`, `files_skipped`, `files_to_scan`, `files_analyzed`, `findings_found`), `result`, `error`. Shared under a `threading.Lock`. In-memory only.

**Scanner entry point**

```
File: scanner/engine.py
Responsibility: scan pipeline orchestration + finding grouping.
Important functions:
  scan_root(root, files, progress) -> ScanResult   # filter→detect→rule match→score→group
  group_findings(findings) -> list[dict]           # dedupe by (rule_id, category), aggregate locations, add beginner/technical
  _report()                                        # null-safe progress callback
```

**Scanner/rule architecture**

```
File: scanner/rules/base.py
Responsibility: Rule dataclass — declarative regex rules with metadata + templated Finding construction.
Important functions/methods: applies_to(target), should_scan_file(path), find_in(content), make_finding(...)
```

Rules are plain `Rule(...)` objects assembled in `RULES` lists, one module per category. `scanner/rules/__init__.py` `all_rules()` concatenates all 10 module lists (~54 rules). Each rule carries `rule_id`, `category`, `severity`, `confidence`, `description`, `why_it_matters`, `recommendation`, `ai_fix_prompt`, `patterns` (regex list) and/or a custom `match` callable, plus `files_include`/`files_exclude`/`frameworks` filters.

**Result generation**

```
File: scanner/scoring.py
Responsibility: Ship Score + grade. Dedupe by (rule_id, category); penalty per severity × confidence weight; floor 0, cap 100; grade bands (90/75/50/25).
Important functions: compute_score(findings) -> (score, grade), status_for_score(score)
File: scanner/scope.py
Responsibility: which files are analyzed; finding priority; actionability.
Important functions: should_analyze(path), is_ignored(path), priority_for(sev, conf), is_actionable(finding), severity_order(sev)
File: scanner/redaction.py
Responsibility: mask secret-looking evidence before it reaches output.
Important functions: redact_evidence(snippet, max_len), mask_secret(value)
File: scanner/messaging.py
Responsibility: beginner-friendly copy lookup (per-rule override → category fallback → generic).
Important functions: beginner_for(rule_id, category, title, description, why_it_matters, recommendation)
```

**Report generation** — server-rendered HTML in `backend/main.py:_render_report` (no template engine; f-string). Frontend additionally renders a richer interactive report and can build a fallback HTML report in `app.js:buildReportHtml`.

## 5. Frontend Architecture

All vanilla JS, DOM-referenced via an `els` map at top of `app.js`.

- **HTML entry point**: `frontend/index.html` — five `<section class="view">` blocks toggled via the `hidden` attribute: `view-landing`, `view-upload`, `view-progress`, `view-scan-complete`, `view-results`. Includes SVG score ring, findings/passed containers.
- **JS entry point**: `frontend/app.js`, loaded at end of body. Runs on load; wires all event listeners.
- **Application state**: module-level variables in `app.js` — `selectedFile`, `currentScanId`, `currentResult`, `lastAnnouncedPhase`, `lastAnnouncedMessage`, `activityEntries[]`, `activityCurrent` (progress log). No framework/state store.
- **API communication**: 
  - `uploadScan(file, ...)` — `XMLHttpRequest` POST `/api/scans` with FormData (for upload progress events).
  - `fetchScanStatus(scanId)` / `pollScan(scanId)` — `fetch` polling of `GET /api/scans/{id}` every 700 ms (`POLL_INTERVAL_MS`), max 4 transport errors.
  - `downloadReport()` — `fetch` of `GET /api/scans/{id}/report`; saves returned HTML blob (or `buildReportHtml` fallback).
- **Scan UI**: `runScan(file)` → shows progress view, resets UI, uploads, then polls.
- **Progress tracker**: `renderProgress(p)` (phase title/message), `pushActivity(p)` + `activitySection(entry, isCurrent)` (terminal-style log lines), `renderActivity()`, `progressPercent(p)`, `resetProgressUi()`. Terminal look: `> Phase`, `[████░] 42%`, `└─ file.ts`, findings counter.
- **Report renderer**: `renderResults(result)` (results view with animated score ring + summary).
- **Finding renderer**: `renderFindings(groups, result)` groups into FIX FIRST / REVIEW / SUGGESTIONS sections; `buildFindingCard(group, index)` builds each card (beginner copy, locations, AI fix prompt toggle + copy, technical details).
- **Other**: `renderScanComplete(result)` (interstitial screen), `renderPassed(passed)` (passed-check chips), `renderError(message)`, `gradeForScore(score)`, `redactEvidence(evidence)` (client-side redaction fallback), `copyText`/`fallbackCopy`.
- **CSS structure**: `frontend/styles.css` — CSS variables (`:root`) with GitHub-dark palette; sections: base/reset, header/footer, buttons, hero/features, panels/dropzone, progress terminal (`progress-activity`, `activity-*`), score ring, finding cards (`finding-card`, `severity-badge`, `fix-prompt`), passed chips, media queries, `prefers-reduced-motion`.

## 6. Scan Data Flow

```
user clicks "Upload & Scan" (app.js runScan)
  → XHR POST /api/scans (FormData "file")        backend/main.py create_scan
  → _save_upload validates content-type/.zip, size ≤100MB (413)
  → scan_id = uuid hex12; ScanState created; asyncio.to_thread(_run_scan)
  → _run_scan:
      safe_extract_zip(zip)                      scanner/ziputils.py (zip-slip/bomb/symlink/limit checks)
      iter_text_files(ws, progress=discovery)     scanner/ziputils.py → FileSnapshot list
      scan_root(ws, files, progress)              scanner/engine.py
        should_analyze filter                     scanner/scope.py
        detect_scan_target                        scanner/detection.py
        rules = all_rules() ∩ applies_to(target)  scanner/rules/
        per file: rule.find_in(content) → hits
          → redact_evidence(ev)                   scanner/redaction.py
          → rule.make_finding → priority_for      scanner/rules/base.py, scanner/scope.py
        compute_score(findings)                   scanner/scoring.py
        group_findings(findings)                  scanner/engine.py
        ScanResult.to_dict()
  → state.result stored; state → complete; _storage[scan_id] = result (TTL 3600s)
  → frontend poll GET /api/scans/{id} (700ms)
      running → renderProgress(progress)
      complete → renderScanComplete(result) → "Review Report" → renderResults(result)
  → GET /api/scans/{id}/report → _render_report() HTML (or frontend buildReportHtml)
```

## 7. Progress System

V1.3 introduced the live terminal-style tracker.

- **Origin of state**: `ScanState` in `backend/main.py`; counters mutated via `_apply_state` under a lock.
- **Communication**: scanner emits phase-tagged field dicts through `progress` callbacks created by `_report_progress(state)` and `_report_discovery(state)` in `backend/main.py`. `scan_root` calls the callback at `filtering`, per-file `scanning`, `reviewing`, and final `building_report` (see `scanner/engine.py:scan_root`). Discovery counter emitted inside `ziputils.iter_text_files`.
- **Frontend reception**: `pollScan` → `renderProgress(data.progress)` in `frontend/app.js`. Phase titles map in `PHASE_TITLES`; per-phase terminal lines in `activitySection`.
- **Terminal UI rendering**: `pushActivity` maintains an ordered log (`activityEntries` + `activityCurrent`); `renderActivity` rebuilds `#progress-activity`. Bars via block chars `█`/`░`, progress from `current/total` (`progressPercent`). Styled by `.progress-activity`/`.activity-*` in `styles.css`.
- **Relevant files/functions**: `backend/main.py` (`ScanState`, `_apply_state`, `_report_progress`, `_report_discovery`, `get_scan`), `scanner/engine.py:scan_root`, `scanner/ziputils.py:iter_text_files`, `frontend/app.js` (`pollScan`, `renderProgress`, `pushActivity`, `activitySection`, `renderActivity`, `renderError`), `frontend/styles.css` (`.progress-activity` etc.).

## 8. Report System

- **Score/grade**: `scanner/scoring.py:compute_score` → `ScanResult.score`/`grade`; frontend re-derives label+color via `gradeForScore` (`app.js`); backend report uses `result.grade` string directly.
- **Findings**: `ScanResult.groups` (grouped by rule_id+category, sorted by severity then location count). Severity labels for cards: `SEVERITY_TEXT` in `app.js`; backend `_render_report` `sev_label`.
- **Severity**: enum in `scanner/models.py:Severity`; used for ordering, score penalty, and UI color (`SEVERITY_COLORS` in `app.js`).
- **Beginner messaging**: `scanner/messaging.py:beginner_for` populates `group["beginner"]` (title/summary/why_it_matters/recommended_action + technical fields) in `engine.group_findings`. Frontend renders beginner copy first; technical fields in collapsible "Technical details".
- **Advanced details**: `group["technical"]` (name, rule_id, confidence, severity) + raw description/evidence in the `<details>` block (`app.js:buildFindingCard`, `frontend/styles.css .tech-details`).
- **Passed checks**: `scan_root` computes `passed = {r.rule_id for r in rules if r.rule_id not in rule_hits}`; `ScanResult.passed`; rendered as green chips by `app.js:renderPassed`.
- **AI fix prompt**: authored per rule (`Rule.ai_fix_prompt`), carried on every finding and group; `buildFindingCard` renders "View AI Fix Prompt" toggle + "Copy" button (`app.js`).
- **Report rendering**: two renderers — `backend/main.py:_render_report` (standalone HTML served by `/report`; score banner, top-5 cards, collapsible extra observations, severity count line) and `frontend/app.js:renderResults`/`buildFindingCard` (interactive in-app view) + `buildReportHtml` (client-side fallback download HTML).

## 9. Important Data Structures

- **`Finding`** (`scanner/models.py`) — `rule_id, severity, confidence, category, title, file, line, evidence, description, why_it_matters, recommendation, ai_fix_prompt, technical, beginner, priority`. `to_dict()` flattens to JSON.
- **`ScanResult`** (`scanner/models.py`) — `findings, groups, project_type, frameworks, files_scanned, application_files, ignored_files, duration_ms, score, grade, summary, passed`. `to_dict()` → API JSON.
- **`groups`** (list of dicts, built in `engine.group_findings`) — the key frontend contract: `rule_id, category, title, severity, confidence, priority, description, why_it_matters, recommendation, ai_fix_prompt, locations[{file,line,evidence}], beginner{...}, technical{...}`.
- **`ScanState`** (`backend/main.py`) — live progress + result carrier; `to_dict()` → `progress` field of running-scan response.
- **Progress event** (dict passed through callbacks) — keys: `phase` (`filtering|scanning|reviewing|building_report|discovering`), `current`, `total`, `current_file`, `files_discovered`, `files_skipped`, `files_to_scan`, `files_analyzed`, `findings_found`.
- **`FileSnapshot`** (`scanner/models.py`) — `path, content, binary`.
- **`ScanTarget`** (`scanner/models.py`) — `root, files, project_type, frameworks` (set).

## 10. API/Data Contracts

- `GET /health` → `{"status":"ok","service":"ship-safe"}`.
- `POST /api/scans` — multipart field `file` (ZIP only). 400 non-zip / bad extension; 413 >100MB. Returns `{"scan_id","status":"running"}` immediately; scan runs async.
- `GET /api/scans/{scan_id}` — running → `{"scan_id","status":"running","progress": ScanState.to_dict()}`; complete → `{"scan_id","status":"complete","result": ScanResult.to_dict()}`; error → `{"scan_id","status":"error","error": msg}`; unknown → 404.
- `GET /api/scans/{scan_id}/report` → `text/html` standalone report (404 if expired/unknown). Results stored in-memory for 3600s (`REPORT_TTL_S`).
- **Static frontend** served at `/` via `StaticFiles(directory=frontend, html=True)`.

## 11. Tests

- `tests/unit/test_rules.py` — per-rule true positives/negatives (secrets, git, config, api, auth, payments, code, deploy), redaction masking.
- `tests/unit/test_scoring.py` — score bands, penalties, confidence weighting, dedup, info-flood floor.
- `tests/unit/test_messaging.py` — beginner copy resolution (rule override / category / fallback).
- `tests/unit/test_scope.py` — excluded dirs/artifacts, app source inclusion, Windows paths.
- `tests/unit/test_progress.py` — `scan_root` emits filtering/scanning/building_report events with correct counters; callback does not alter results.
- `tests/integration/test_scanner.py` — engine detects vulns, clean project low-FP, secret redaction, framework reporting.
- `tests/integration/test_api.py` — full API flow: health, scan→poll→result, ZIP validation, malformed-zip error state, progress payload, report HTML, 404, cleanup.
- `tests/integration/test_scope_engine.py` — vendor exclusion, grouping/dedup, low-confidence deprioritization, group penalty once, data contract.
- `tests/integration/test_ziputils.py` — file iteration, callbacks, binary/large/encoding handling.
- `tests/security/test_zip_safety.py` — zip-slip, absolute paths, zip bombs, entry/symlink limits, nested-zip rejection.
- Fixtures: `tests/fixtures/vuln/` (app.py, app/checkout.py, app/db_app.py with seeded vulnerabilities) and `tests/fixtures/clean/` (`conftest.py` provides `vuln_project`, `clean_project`, `vuln_zip`, `clean_zip`).

## 12. Architectural Constraints

- **Framework choice**: FastAPI backend; vanilla JS frontend (no npm/build). Do not add a JS framework or build step without explicit reason.
- **Scanner is deterministic and self-contained**: pure regex/static analysis, no LLM, no network calls during scanning. Evidence must pass through `redaction.py` before output.
- **Scanner engine is decoupled from web layer**: `scanner/` imports nothing from `backend/`; rules must stay framework-independent (no HTTP/route coupling).
- **No DB, no Redis, no queues, no microservices**: in-memory dict storage only; scan runs in a thread via `asyncio.to_thread` (sync pipeline).
- **Scoring behavior is fixed**: penalties Critical 20 / High 12 / Medium 6 / Low 2 / Info 0, weighted by confidence (1.0/0.75/0.5), dedup by (rule_id, category), grade bands 90/75/50/25. Tests pin this.
- **Severity ordering**: `critical < high < medium < low < informational` via `scope.severity_order`.
- **Actionability**: `scope.is_actionable` — high-confidence findings, or medium-confidence with evidence.
- **Rule cap**: `MAX_FINDINGS_PER_RULE_PER_FILE = 5` per rule per file.
- **ZIP limits**: 100MB upload, 5000 entries, 200MB uncompressed, 10MB/file, 200× ratio, no symlinks, no path escape; files deleted post-scan.
- **Python ≥3.12**; deps pinned in `requirements.txt`/`pyproject.toml`. Docker images copy `scanner/`, `backend/`, `frontend/`.
- **Report TTL**: 3600s in-memory.

## 13. Reuse Before Creating

- **Adding a detection rule** → append to existing `RULES` list in the matching `scanner/rules/<category>.py` (reuse `Rule` from `base.py`); register nothing manually (`all_rules()` iterates modules). ~54 rules across 10 categories already exist.
- **Beginner copy for a new category/rule** → extend `scanner/messaging.py` `_CATEGORY` / `_RULES` maps.
- **New file filters / priorities** → `scanner/scope.py` (`EXCLUDED_DIRS`, `EXCLUDED_SUFFIXES`, `priority_for`, `is_actionable`).
- **Framework detection** → `scanner/detection.py` (`MANIFESTS`, `FRAMEWORK_MARKERS`).
- **Score/grade changes** → `scanner/scoring.py`.
- **API/endpoint changes** → `backend/main.py` (all routes + state live there; static frontend mounted last — mount ordering matters).
- **Frontend views/rendering** → `frontend/app.js` (views, `renderResults`, `renderFindings`, `buildFindingCard`, progress UI) + `frontend/index.html` + `frontend/styles.css`.
- **Report HTML** → `backend/main.py:_render_report` (server-side) or `frontend/app.js:buildReportHtml` (client fallback); keep both consistent if report copy changes.
- **ZIP handling** → `scanner/ziputils.py` (do not write new extraction code).
- **Finding/report data shape** → `scanner/models.py` + `engine.group_findings` (frontend depends on `groups[].locations/beginner/technical`).

## 14. Known Caveats

- **Two parallel report renderers**: the backend standalone HTML (`_render_report`) and the interactive frontend report (`renderResults`/`buildFindingCard`) duplicate report logic; changes to copy (e.g. severity labels, grade bands) must be applied in both places — plus `gradeForScore`/`SEVERITY_TEXT` in `app.js` duplicate `scoring.py` grade bands and `messaging.py` labels.
- **Case-insensitive filesystem**: the repo is checked out on Windows; `docs/` and `DOCS/` are the same directory.
- **`backend/__init__.py` and `scanner/__init__.py` are near-empty** — imports rely on path-based package resolution (`PYTHONPATH`/workspace); the dev console script is `run:main` but the Docker image runs `uvicorn backend.main:app` directly.
- **In-memory state is single-process**: `_storage`/`_active` dicts mean results are lost on restart and don't survive multi-worker deployment; only one process should serve (`uvicorn` without workers).
- **`docs/ARCHITECTURE.md` describes a planned structure (e.g. `scanner/core/`, `scanner/analyzers/`, `backend/api/`) that the actual code does not match** — code lives flat in `scanner/` and `backend/main.py`. Trust the code, not that doc.
- **Upload progress is simulated**: `current/total` bytes in the uploading phase are real XHR progress, but the backend has no upload-phase state; frontend drives that phase locally.
- **Frontend re-renders the entire activity log on every progress tick** (`renderActivity` rebuilds children), which is fine for small logs but could become a perf concern on very large scans.
- **Report download prefers the server HTML blob**; `buildReportHtml` runs only if the server returns non-HTML content.

## 15. Maintenance Rule

This document is an architectural map, not the source of truth.
The current source code takes precedence if this document becomes outdated.
