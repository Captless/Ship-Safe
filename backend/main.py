from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
import time
import traceback
import uuid

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from scanner.ziputils import safe_extract_zip, iter_text_files, cleanup_workspace, ZipSafetyError
from scanner.engine import scan_root

MAX_UPLOAD = 100 * 1024 * 1024
REPORT_TTL_S = 3600

app = FastAPI(title="Ship Safe", version="1.0.0")

FRONTEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")

_storage: dict[str, dict] = {}
_active: dict[str, "ScanState"] = {}
_lock = threading.Lock()


class ScanState:
    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self.status = "running"
        self.phase = "uploading"
        self.message = "Uploading your project"
        self.current: int | None = None
        self.total: int | None = None
        self.current_file: str | None = None
        self.files_discovered: int | None = None
        self.files_skipped: int | None = None
        self.files_to_scan: int | None = None
        self.files_analyzed: int | None = None
        self.findings_found: int | None = None
        self.result: dict | None = None
        self.error: str | None = None
        self.created = time.time()

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "message": self.message,
            "current": self.current,
            "total": self.total,
            "current_file": self.current_file,
            "files_discovered": self.files_discovered,
            "files_skipped": self.files_skipped,
            "files_to_scan": self.files_to_scan,
            "files_analyzed": self.files_analyzed,
            "findings_found": self.findings_found,
        }


def _apply_state(state: ScanState, **kwargs) -> None:
    with _lock:
        for key, value in kwargs.items():
            if value is not None:
                setattr(state, key, value)


def _report_progress(state: ScanState):
    def report(fields: dict) -> None:
        phase = fields.pop("phase", None)
        if phase == "scanning":
            _apply_state(state, phase="scanning", message="Checking your code", **fields)
        elif phase == "filtering":
            _apply_state(state, phase="filtering", message="Filtering files", **fields)
        elif phase == "reviewing":
            _apply_state(state, phase="reviewing", message="Reviewing findings")
        elif phase == "building_report":
            _apply_state(state, phase="building_report", message="Preparing your report", **fields)
    return report


def _report_discovery(state: ScanState):
    def report(fields: dict) -> None:
        _apply_state(state, phase="discovering", message="Discovering project files", **fields)
    return report


def _save_upload(upload: UploadFile) -> str:
    if upload.content_type not in ("application/zip", "application/x-zip-compressed", ""):
        raise HTTPException(status_code=400, detail="Only ZIP files are supported.")
    name = upload.filename or ""
    if not name.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="File must have a .zip extension.")
    tmp = tempfile.NamedTemporaryFile(prefix="shipsafe_upload_", suffix=".zip", delete=False)
    try:
        size = 0
        while True:
            chunk = upload.file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_UPLOAD:
                tmp.close()
                os.unlink(tmp.name)
                raise HTTPException(status_code=413, detail="Upload too large (max 100 MB).")
            tmp.write(chunk)
        tmp.close()
        return tmp.name
    finally:
        if not tmp.closed:
            tmp.close()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "ship-safe"}


@app.post("/api/scans")
async def create_scan(file: UploadFile = File(...)) -> dict:
    zip_path = _save_upload(file)
    scan_id = uuid.uuid4().hex[:12]
    state = ScanState(scan_id)
    with _lock:
        _active[scan_id] = state
    _prune_storage()
    asyncio.create_task(asyncio.to_thread(_run_scan, scan_id, zip_path))
    return {"scan_id": scan_id, "status": "running"}


def _run_scan(scan_id: str, zip_path: str) -> None:
    state = _active.get(scan_id)
    if state is None:
        return
    workspace = None
    try:
        _apply_state(state, phase="preparing", message="Preparing your project")
        workspace = safe_extract_zip(zip_path)
        _apply_state(state, phase="discovering", message="Discovering project files")
        files = list(iter_text_files(workspace, progress=_report_discovery(state)))
        _apply_state(state, files_discovered=len(files))
        result = scan_root(workspace, files, progress=_report_progress(state))
        result_dict = result.to_dict()
        _apply_state(state, phase="building_report", message="Preparing your report")
        _apply_state(state, result=result_dict)
        _apply_state(state, phase="complete", status="complete", message="Scan complete")
        with _lock:
            _storage[scan_id] = {"result": result_dict, "created": time.time()}
            _active.pop(scan_id, None)
    except ZipSafetyError as e:
        _fail_scan(state, f"Could not open the archive. {e}")
    except Exception:
        traceback.print_exc()
        _fail_scan(state, "We couldn't finish analyzing this project. The archive may be malformed.")
    finally:
        if zip_path and os.path.exists(zip_path):
            try:
                os.unlink(zip_path)
            except OSError:
                pass
        if workspace:
            cleanup_workspace(workspace)


def _fail_scan(state: ScanState, message: str) -> None:
    _apply_state(state, status="error", phase="error", message="Scan could not be completed", error=message)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    with _lock:
        state = _active.get(scan_id)
    if state is not None:
        if state.status == "complete":
            return {"scan_id": scan_id, "status": "complete", "result": state.result}
        if state.status == "error":
            return {"scan_id": scan_id, "status": "error", "error": state.error or "The scan failed."}
        return {"scan_id": scan_id, "status": "running", "progress": state.to_dict()}
    entry = _storage.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {"scan_id": scan_id, "status": "complete", "result": entry["result"]}


def _prune_storage() -> None:
    now = time.time()
    for k in list(_storage):
        if now - _storage[k]["created"] > REPORT_TTL_S:
            del _storage[k]
    with _lock:
        for k in list(_active):
            if now - _active[k].created > REPORT_TTL_S:
                del _active[k]


@app.get("/api/scans/{scan_id}/report")
def get_report(scan_id: str) -> HTMLResponse:
    entry = _storage.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Scan not found.")
    result: dict = entry["result"]
    html = _render_report(scan_id, result)
    return HTMLResponse(html)


def _render_report(scan_id: str, result: dict) -> str:
    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    groups = result.get("groups", [])
    summary = result.get("summary", {})
    score = result.get("score", 100)
    grade = result.get("grade", "REVIEW BEFORE SHIPPING")

    if score >= 90:
        hero_title = "IS LOOKING GOOD"
    elif score >= 75:
        hero_title = "IS ALMOST READY"
    elif score >= 50:
        hero_title = "NEEDS ATTENTION"
    else:
        hero_title = "DON'T SHIP YET"

    actionable = [g for g in groups if g.get("severity") in ("critical", "high", "medium")]
    minor = [g for g in groups if g.get("severity") not in ("critical", "high", "medium")]

    sev_order = ["critical", "high", "medium", "low", "informational"]
    sev_labels = {
        "critical": "Fix before shipping",
        "high": "Worth reviewing",
        "medium": "Worth reviewing",
        "low": "Good to know",
        "informational": "Good to know",
    }
    counts = {s: sum(1 for g in groups if g.get("severity") == s) for s in sev_order}
    count_line = " ".join(f"{sev_labels[s]} {counts[s]}" for s in sev_order if counts[s])

    if counts.get("critical"):
        next_step = "Fix the critical issues first. The remaining items can be reviewed afterward."
    elif counts.get("high") or counts.get("medium"):
        next_step = "Review the highlighted issues and fix the ones that matter for your app before you ship."
    elif counts.get("low") or counts.get("informational"):
        next_step = "These are minor suggestions. Review them when you have time."
    else:
        next_step = "Continue with your normal testing and deployment review."

    prompt_lines = []
    if actionable:
        prompt_lines.append(
            f"Ship Safe found {len(actionable)} issue{'s' if len(actionable) != 1 else ''} worth fixing before you ship."
        )
        prompt_lines.append("")
        prompt_lines.append("Instructions:")
        prompt_lines.append("\n".join([
            "Inspect the existing project first.",
            "Understand the existing architecture and conventions before making changes.",
            "Address each listed finding with the smallest appropriate change.",
            "Do not create duplicate files or duplicate existing modules.",
            "Preserve existing behavior unless a finding requires changing it.",
            "Avoid unrelated refactoring.",
            "Verify your changes by running the relevant tests.",
            "Summarize what you changed and why.",
        ]))
        for i, g in enumerate(actionable):
            b = g.get("beginner", {})
            locs = g.get("locations", [])
            first = locs[0] if locs else {}
            where = first.get("file", "unknown location")
            if first.get("line"):
                where += f":{first['line']}"
            prompt_lines.append("")
            prompt_lines.append(f"{i + 1}. {str(g.get('severity', '')).upper()} — {b.get('title') or g.get('title') or 'Finding'}")
            prompt_lines.append(f"   Where: {where}")
            prompt_lines.append(f"   What happened: {b.get('summary') or g.get('description') or ''}")
            prompt_lines.append(f"   Why it matters: {b.get('why_it_matters') or g.get('why_it_matters') or ''}")
            prompt_lines.append(f"   What to do: {b.get('recommended_action') or g.get('recommendation') or ''}")
            if g.get("ai_fix_prompt"):
                prompt_lines.append(f"   Suggested fix: {g['ai_fix_prompt']}")
        consolidated = "\n".join(prompt_lines)
    else:
        consolidated = ""

    def card(g):
        b = g.get("beginner", {})
        locs = g.get("locations", [])
        first = locs[0] if locs else {}
        extra = ""
        if len(locs) > 1:
            others = "".join(
                f"<li>{esc(l.get('file', ''))}{':' + esc(str(l.get('line', ''))) if l.get('line') else ''}</li>"
                for l in locs[1:]
            )
            extra = f"<details class='locs'><summary>{len(locs)} locations detected</summary><ul>{others}</ul></details>"
        title = esc(b.get("title") or g.get("title", "Finding"))
        html = (
            "<div class='card'>"
            f"<div class='head'><span class='sev {esc(g.get('severity', ''))}'>{esc(g.get('severity', ''))}</span>"
            f"<span class='rid'>{esc(g.get('rule_id', ''))}</span></div>"
            f"<h3>{title}</h3>"
            + (f"<p>{esc(b.get('summary') or '')}</p>" if b.get("summary") else "")
            + (f"<p class='why'><strong>Why it matters:</strong> {esc(b.get('why_it_matters') or '')}</p>" if b.get("why_it_matters") else "")
            + (f"<p class='rec'><strong>What to do:</strong> {esc(b.get('recommended_action') or '')}</p>" if b.get("recommended_action") else "")
            + (
                f"<p class='loc'><strong>Found in:</strong> {esc(first.get('file', ''))}"
                + (f":{esc(str(first.get('line')))}" if first.get('line') else "")
                + "</p>"
                if first
                else ""
            )
            + extra
            + "</div>"
        )
        return html

    cards = "\n".join(card(g) for g in actionable) if actionable else "<p>No actionable findings detected. Perform a final review before shipping.</p>"
    obs_html = ""
    if minor:
        obs_count = sum(len(g.get("locations", [])) for g in minor)
        obs_cards = "\n".join(card(g) for g in minor)
        obs_html = (
            f"<h2>{obs_count} additional low-priority observations</h2>"
            f"<details><summary>Show details</summary>{obs_cards}</details>"
        )

    passed = result.get("passed", [])
    label_map = [
        ("SECRET-", "secrets", "No obvious exposed secrets"),
        ("GIT-", "git", "No risky version-control files"),
        ("CONF-", "config", "No unsafe configuration defaults"),
        ("DB-", "database", "No database credential exposure"),
        ("AUTH-", "auth", "Authentication checks look present"),
        ("API-", "api", "API input validation looks present"),
        ("PAY-", "payments", "Payment handling looks reasonable"),
        ("CODE-", "code", "No dangerous code patterns detected"),
        ("DEPLOY-", "deploy", "No insecure deployment settings"),
        ("DEP-", "dependencies", "Dependencies look reasonable"),
    ]
    cats_with_findings = {g.get("category") for g in groups}
    good_rows = []
    for prefix, cat, label in label_map:
        ran = any(isinstance(r, str) and r.startswith(prefix) for r in passed)
        if ran and cat not in cats_with_findings:
            good_rows.append(label)
    good_html = "".join(f"<span class='ok'>&#10003; {esc(label)}</span> " for label in good_rows)
    good_html = good_html or "<p class='meta'>No passed checks recorded for this scan.</p>"

    scan_info = (
        f"{esc(result.get('files_scanned', 0))} files scanned · "
        f"{esc(result.get('application_files', 0))} application files · "
        f"{esc(result.get('ignored_files', 0))} ignored/generated/vendor files · "
        f"{esc(result.get('duration_ms', 0))} ms"
    )

    summary_line = (
        f"{esc(result.get('files_scanned', 0))} files analyzed · "
        f"{esc(result.get('application_files', 0))} application files · "
        f"{esc(result.get('ignored_files', 0))} ignored/generated/vendor files · "
        f"{esc(summary.get('actionable_findings', 0))} actionable findings"
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ship Safe Report</title><style>
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;max-width:860px;margin:0 auto;padding:24px}}
.banner{{font-family:monospace;text-transform:uppercase;letter-spacing:2px;color:#2dd4bf;font-weight:800}}
.meta{{color:#8b949e}}
.hero{{text-align:center;margin:16px 0 8px}}
.hero-eyebrow{{font-family:monospace;text-transform:uppercase;letter-spacing:3px;color:#8b949e;margin:0}}
.hero-title{{font-family:monospace;font-size:28px;margin:6px 0 0;letter-spacing:1px}}
.score{{font-size:56px;font-weight:800;color:#2dd4bf}}
.status{{font-family:monospace;text-transform:uppercase;color:#fbbf24;font-weight:700}}
.priority{{font-family:monospace;font-size:13px;color:#8b949e}}
.card{{border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0;background:#161b22}}
.head{{display:flex;align-items:center;gap:8px;margin-bottom:6px}}
.sev{{font-weight:700;text-transform:uppercase;font-size:12px;padding:2px 8px;border-radius:4px}}
.critical{{background:#f85149;color:#fff}} .high{{background:#d29922;color:#0d1117}}
.medium{{background:#388bfd;color:#fff}} .low{{background:#58a6ff;color:#0d1117}} .informational{{background:#30363d;color:#c9d1d9}}
.rid{{color:#8b949e;margin-left:8px;font-family:monospace}}
.loc{{font-family:monospace;color:#2dd4bf}}
.locs{{margin:8px 0 0}} .locs ul{{margin:6px 0 0;color:#8b949e}}
.ok{{color:#3fb950;font-family:monospace;margin-right:14px}}
pre{{background:#0d1117;border:1px solid #30363d;padding:12px;border-radius:6px;white-space:pre-wrap}}
.why{{color:#c9d1d9}} .rec{{color:#c9d1d9}}
</style></head><body>
<p class="banner">Build check complete</p>
<p class="meta">{summary_line}</p>
<div class="hero">
<p class="hero-eyebrow">Your project</p>
<h1 class="hero-title">{hero_title}</h1>
<div class="score">{score}</div><div class="status">{grade}</div>
<p class="meta">{'Your AI-built project was analyzed.'}</p>
<p class="priority">{count_line}</p>
</div>
<h2>Your next step</h2>
<p>{next_step}</p>
{f"<h2>Fix these issues with AI</h2><pre>{esc(consolidated)}</pre>" if consolidated else ""}
<h2>Findings</h2>
{cards}
{obs_html}
<h2>What's already good</h2>
<p>{good_html}</p>
<h2>Scan information</h2>
<p class="meta">{scan_info}</p>
</body></html>"""


app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
