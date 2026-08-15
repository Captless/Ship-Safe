from __future__ import annotations

import json
import os
import tempfile
import time
import uuid

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from scanner.ziputils import safe_extract_zip, iter_text_files, cleanup_workspace, ZipSafetyError
from scanner.engine import scan_root
from scanner.models import ScanResult

MAX_UPLOAD = 100 * 1024 * 1024
ALLOWED_EXTS = {".zip"}
REPORT_TTL_S = 3600

app = FastAPI(title="Ship Safe", version="1.0.0")

FRONTEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")

_storage: dict[str, dict] = {}


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
    zip_path = None
    workspace = None
    try:
        zip_path = _save_upload(file)
        workspace = safe_extract_zip(zip_path)
        files = list(iter_text_files(workspace))
        result = scan_root(workspace, files)
        scan_id = uuid.uuid4().hex[:12]
        _storage[scan_id] = {
            "result": result.to_dict(),
            "created": time.time(),
        }
        _prune_storage()
        return {"scan_id": scan_id, "status": "complete", "result": result.to_dict()}
    except HTTPException:
        raise
    except ZipSafetyError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="Scan failed. The archive may be malformed.")
    finally:
        if zip_path and os.path.exists(zip_path):
            try:
                os.unlink(zip_path)
            except OSError:
                pass
        if workspace:
            cleanup_workspace(workspace)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    entry = _storage.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {"scan_id": scan_id, "status": "complete", "result": entry["result"]}


def _prune_storage() -> None:
    now = time.time()
    for k in list(_storage):
        if now - _storage[k]["created"] > REPORT_TTL_S:
            del _storage[k]


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
    sev = summary.get("findings_by_severity", {})
    score = result.get("score", 100)
    status = result.get("grade", "REVIEW BEFORE SHIPPING")

    def counts(sev_value):
        return sum(1 for g in groups if g.get("severity") == sev_value)

    sev_order = ["critical", "high", "medium"]
    sev_label = {"critical": "Critical", "high": "High", "medium": "Medium"}
    count_line = " ".join(
        f"{sev_label[s]} {counts(s)}" for s in sev_order
    )

    def card(g, primary=False):
        locs = g.get("locations", [])
        first = locs[0] if locs else {}
        extra = ""
        if len(locs) > 1:
            others = "".join(
                f"<li>{esc(l.get('file',''))}{':' + esc(str(l.get('line',''))) if l.get('line') else ''}</li>"
                for l in locs[1:]
            )
            extra = f"<details class='locs'><summary>{len(locs)} locations detected</summary><ul>{others}</ul></details>"
        title = esc(g.get("title", "Finding"))
        if primary:
            title = "<strong>" + title + "</strong>"
        return (
            "<div class='card'>"
            f"<div class='head'><span class='sev {esc(g.get('severity',''))}'>{esc(g.get('severity',''))}</span>"
            f"<span class='rid'>{esc(g.get('rule_id',''))}</span></div>"
            f"<h3>{title}</h3>"
            f"<p class='loc'>{esc(first.get('file',''))}{':' + esc(str(first.get('line',''))) if first.get('line') else ''}</p>"
            + (f"<p><strong>What we found:</strong> {esc(g.get('description',''))}</p>" if g.get("description") else "")
            + (f"<p class='why'><strong>Why it matters:</strong> {esc(g.get('why_it_matters',''))}</p>" if g.get("why_it_matters") else "")
            + (f"<p class='rec'><strong>What to do:</strong> {esc(g.get('recommendation',''))}</p>" if g.get("recommendation") else "")
            + (f"<details><summary>Show AI fix prompt</summary><pre>{esc(g.get('ai_fix_prompt',''))}</pre></details>" if g.get("ai_fix_prompt") else "")
            + extra
            + "</div>"
        )

    top = groups[:5]
    cards = "\n".join(card(g, i == 0) for i, g in enumerate(top)) if top else ""
    obs_groups = groups[5:]
    obs_count = sum(len(g.get("locations", [])) for g in obs_groups)
    obs_html = ""
    if obs_count:
        obs_cards = "\n".join(card(g) for g in obs_groups)
        obs_html = (
            f"<h2>{obs_count} additional low-priority observations</h2>"
            f"<details><summary>Show details</summary>{obs_cards}</details>"
        )
    if not groups:
        cards = "<p>No findings detected. Perform a final review before shipping.</p>"

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
.score{{font-size:56px;font-weight:800;color:#2dd4bf}}
.status{{font-family:monospace;text-transform:uppercase;color:#fbbf24;font-weight:700}}
.card{{border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0;background:#161b22}}
.sev{{font-weight:700;text-transform:uppercase;font-size:12px;padding:2px 8px;border-radius:4px}}
.critical{{background:#f85149;color:#fff}} .high{{background:#d29922;color:#0d1117}}
.medium{{background:#388bfd;color:#fff}} .low{{background:#58a6ff;color:#0d1117}} .informational{{background:#30363d;color:#c9d1d9}}
.rid{{color:#8b949e;margin-left:8px;font-family:monospace}}
.loc{{font-family:monospace;color:#2dd4bf}}
.locs{{margin:8px 0 0}} .locs ul{{margin:6px 0 0;color:#8b949e}}
pre{{background:#0d1117;border:1px solid #30363d;padding:12px;border-radius:6px;white-space:pre-wrap}}
.why{{color:#c9d1d9}} .rec{{color:#c9d1d9}}
</style></head><body>
<p class="banner">Build check complete</p>
<p class="meta">{summary_line}</p>
<p class="meta">Your AI-built project was analyzed.</p>
<div class="score">{score}</div><div class="status">{status}</div>
<p class="meta">{count_line}</p>
<h2>Top issues</h2>
{cards}
{obs_html}
</body></html>"""


app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
