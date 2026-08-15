# Ship Safe — Threat Model

> Status: Draft · Version: 1.0 · Date: 2026-08-15
> Source of truth: `plan.md`

---

## 1. Trust Boundaries

```
                    ┌─────────────────────────────┐
                    │  Untrusted Zone             │
                    │  User-uploaded ZIP contents │
                    └──────────────┬──────────────┘
                                   │  (static read-only access)
                    ┌──────────────▼──────────────┐
                    │  Trusted Zone               │
                    │  Scanner engine + web app   │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │  Scanner host / sandbox     │
                    └─────────────────────────────┘
```

**Primary rule:** Uploaded repositories are **untrusted hostile input**. Static analysis only. The scanner never crosses into executing user content.

---

## 2. Assets

| Asset | Value | Protection Goal |
|-------|-------|-----------------|
| User source code | Privacy-sensitive | Ephemeral, deleted after scan, not logged |
| Secret values in uploaded code | Detectable, must be redacted | Never printed in reports/logs |
| Scanner host | Must not be compromised | No code execution from uploads |
| Temporary workspace | Isolation | Sandboxed, cleaned up |
| Scan results | Product data | Stored without raw source |
| User trust | Brand | No privacy claims beyond actual guarantees |

---

## 3. Threats & Mitigations

### 3.1 ZIP Path Traversal (Zip Slip)

**Threat:** Archive entries with `../` or absolute paths write files outside the extraction directory.

**Mitigations:**
- Resolve and validate every entry path against the extraction root before writing.
- Reject entries whose normalized path escapes the workspace.
- Use Python's `zipfile` with explicit `sanitize`/resolve checks; do not rely on default behavior.
- Reject absolute paths.

**Severity:** Critical

---

### 3.2 ZIP Bomb

**Threat:** Small archive expands to enormous size (compression ratio attack), exhausting disk/memory.

**Mitigations:**
- Enforce maximum uncompressed total size before/during extraction.
- Enforce maximum compression ratio.
- Enforce per-file uncompressed size limit.
- Stream-read entries; abort on limit breach.

**Severity:** Critical

---

### 3.3 Extremely Large Files

**Threat:** Individual file too large to scan safely (memory exhaustion).

**Mitigations:**
- Per-file size limit.
- Stream file reading in chunks for scanning.
- Skip/flag oversized files with informational finding.

**Severity:** High

---

### 3.4 Excessive File Count

**Threat:** Archive with millions of entries causes resource exhaustion.

**Mitigations:**
- Maximum entry count limit.
- Maximum total path length.
- Abort scan with clear error when exceeded.

**Severity:** High

---

### 3.5 Recursive Archive Attacks

**Threat:** Nested archives (ZIP within ZIP) cause unbounded recursion/extraction.

**Mitigations:**
- Detect archive signatures in extracted content.
- Do not recursively extract archives in V1.
- Depth limit if nested extraction is ever added.

**Severity:** Medium

---

### 3.6 Symlinks / Special Files

**Threat:** Symlink entries pointing outside workspace; device files, FIFOs, etc.

**Mitigations:**
- Reject symlink/hardlink entries or extract without following links.
- Verify final resolved path stays within workspace.
- Reject non-regular files.

**Severity:** High

---

### 3.7 Malicious File Content (Payload)

**Threat:** Uploaded files contain scripts/binaries designed to compromise the scanner.

**Mitigations:**
- **Never execute uploaded code.** No `npm install`, `pip install`, build scripts, startup commands, lifecycle scripts, user module imports, or uploaded binaries.
- Static analysis only — files are read as text/binary data.
- Read files with fixed encodings; treat binary files as opaque or skip with flags.
- Never `import`/`eval`/`exec` content from uploads.

**Severity:** Critical

---

### 3.8 Scan Timeout / Long-Running Scans

**Threat:** Malicious or pathological input causes unbounded scan time.

**Mitigations:**
- Global scan timeout.
- Per-rule timeout.
- Early termination on limits.
- Design for later background processing, but keep V1 synchronous with hard caps.

**Severity:** Medium

---

### 3.9 Memory Exhaustion

**Threat:** Huge content loaded into memory at once.

**Mitigations:**
- Chunked file reading.
- Per-file and per-scan memory budgets.
- Do not buffer entire archives in memory.

**Severity:** High

---

### 3.10 Temporary File Cleanup Failure

**Threat:** Uploaded source persists on disk after scan.

**Mitigations:**
- Use `tempfile.mkdtemp()` in isolated workspace.
- Guaranteed cleanup via `try/finally` / context managers.
- Cleanup on error paths too.
- Periodic sweeper for orphaned workspaces (stale-timeout).
- Do not persist raw source; persist results/metadata only.

**Severity:** Medium

---

### 3.11 Secret Leakage via Logs/Errors

**Threat:** Secret values from uploaded code appear in logs or error messages.

**Mitigations:**
- Do not log file contents or secret matches.
- Redact evidence before any output.
- Never expose raw uploaded source in API error responses.
- Structured logging with redaction layer.

**Severity:** Critical

---

### 3.12 Filename/Extension Spoofing

**Threat:** Trusting filenames/extensions to decide file type or safety.

**Mitigations:**
- Do not trust filenames or extensions.
- Sniff content/signatures where behavior depends on file type.
- Treat everything as untrusted data.

**Severity:** Medium

---

### 3.13 Web-Facing Attack Surface

**Threat:** Malicious requests to API endpoints (oversized uploads, malformed ZIPs, concurrent abuse).

**Mitigations:**
- Upload size limit enforced at the API boundary.
- Content-type validation.
- Request timeouts.
- Graceful error responses for invalid uploads.
- (Future) rate limiting when abuse appears.

**Severity:** Medium

---

### 3.14 Compromise of Future Features

**Threat:** Future features (GitHub connect, AI provider integration, accounts, billing) expand attack surface.

**Mitigations:**
- Keep provider interfaces isolated.
- Keep billing/auth out of V1 (per plan).
- Design seams now: `AIProvider` interface, no hardcoded provider keys.

**Severity:** (Future)

---

## 4. Data Handling & Privacy

### 4.1 Lifecycle

```
Upload → temporary isolated workspace → scan → generate findings → delete uploaded source
```

### 4.2 Rules

- Do not persist source code unless explicitly required later.
- If scan history is introduced: store metadata/results, **not** raw source, by default.
- Be explicit in the UI about data handling.
- **Never** make a privacy claim the implementation does not actually satisfy.

---

## 5. Mitigation Matrix Summary

| Threat | Severity | Mitigation | Test Required |
|--------|----------|-----------|---------------|
| Zip Slip | Critical | Path validation | Yes |
| ZIP bomb | Critical | Size/ratio limits | Yes |
| Large files | High | Per-file limits, chunking | Yes |
| File count | High | Entry count limit | Yes |
| Recursive archives | Medium | No recursive extraction | Yes |
| Symlinks | High | Reject/non-follow | Yes |
| Code execution | Critical | Static-only, no exec | Yes |
| Timeout | Medium | Scan + per-rule timeouts | Yes |
| Memory | High | Chunked reads, budgets | Yes |
| Cleanup failure | Medium | Context managers, sweeper | Yes |
| Secret leakage | Critical | Redaction, no log content | Yes |
| Name spoofing | Medium | Content sniffing | Yes |
| Web attack surface | Medium | Boundary validation | Yes |

---

## 6. Related Documents

- [ARCHITECTURE.md](./ARCHITECTURE.md)
- [TEST-PLAN.md](./TEST-PLAN.md)
- [PRD.md](./PRD.md)
