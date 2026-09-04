# api.py
# FastAPI backend for the Sentinel frontend. Per-report analysis is primary;
# cross-tool correlation is secondary (only meaningful when reports share a target).
#
#   POST /extract      : one report file -> findings           (PDF / XML / JSON / text)
#   POST /report-fixes : {name, findings, focus?} -> per-report fixes + false positives
#   POST /correlate    : {findings:[...]} -> related? + confirmed / hidden / common fixes
#   GET  /health
#
# IMPORTANT: the LLM client (call_llm / extract_findings) is SYNCHRONOUS and blocking.
# Calling it directly inside an `async def` handler would block FastAPI's event loop,
# freezing every other request (including /health) until it returns. So every blocking
# call is pushed to a worker thread with run_in_threadpool.

import io
import json
from typing import List

from fastapi import FastAPI, UploadFile, File
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from universal_ingest import extract_findings
from correlate import correlate
import cache
import guardrails
from web_graph import build_web_graph, simulate_cut
from llm import call_llm, FAST_MODELS

app = FastAPI(title="Sentinel Digital Twin API")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


def read_report(raw_bytes: bytes, filename: str) -> str:
    """Turn an uploaded file into text. PDFs get real text extraction."""
    if filename.lower().endswith(".pdf"):
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(raw_bytes))
            return "\n".join((page.extract_text() or "") for page in reader.pages)
        except Exception as e:
            return f"[Could not read PDF: {e}]"
    return raw_bytes.decode("utf-8", "ignore")


def _json_obj(raw: str, fallback: dict) -> dict:
    try:
        s, e = raw.find("{"), raw.rfind("}")
        return json.loads(raw[s:e + 1]) if s != -1 and e != -1 else fallback
    except Exception:
        return fallback


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/extract")
async def extract(file: UploadFile = File(...)):
    """Extract normalized findings from a single uploaded report (any format, incl. PDF).

    Returns an explicit `error` (and empty findings) when the file can't be read, instead
    of inventing an "Unknown" finding that would inflate the counts."""
    raw = await file.read()
    text = read_report(raw, file.filename)
    if len(text.strip()) < 30:
        return {
            "name": file.filename, "findings": [],
            "error": "Could not extract readable text (possibly a scanned / image-only PDF, "
                     "an empty file, or an unsupported binary format).",
        }
    # Layer 1 (detect): scan the untrusted report for prompt-injection BEFORE the LLM reads it.
    security = guardrails.summarize(guardrails.scan_injection(text))

    # Blocking LLM work runs in a worker thread so the event loop stays responsive.
    # (Extraction is hardened - Layer 2 - and returns a Layer-3 output check.)
    findings, out_check = await run_in_threadpool(extract_findings, text, file.filename, True)
    security["output_ok"] = out_check.get("ok", True)
    security["output_reason"] = out_check.get("reason", "")
    return {"name": file.filename, "findings": findings, "error": None, "security": security}


class ReportBody(BaseModel):
    name: str = ""
    findings: List[dict] = []
    focus: str = ""


def _report_fixes(name: str, findings: list, focus: str) -> dict:
    ck = cache.key_for(name, focus, json.dumps(findings, sort_keys=True))
    cached = cache.get("fixes", ck)
    if cached is not None:
        return cached

    system = (
        "You are a security analyst. For THIS ONE report's findings, return ONLY JSON: "
        '{"fixes": ["short prioritized fix, most impactful first", ...], '
        '"false_positives": [{"finding": "...", "why": "one line"}]}. '
        "Keep it to at most ~6 fixes. Put likely-false or low-signal findings in false_positives. "
        "Base everything ONLY on the findings provided for this report."
    )
    if focus.strip():
        system += f" The analyst is specifically focused on: {focus.strip()!r} - prioritize that."
    user = f"REPORT: {name}\nFINDINGS:\n{json.dumps(findings, indent=2)}"
    raw = call_llm(system, user, models=FAST_MODELS)
    out = _json_obj(raw, {"fixes": [], "false_positives": []})
    # Validate/normalize so malformed model output can't break the UI.
    fixes = [str(f) for f in out.get("fixes", []) if isinstance(f, str) and f.strip()][:6]
    fps = [
        {"finding": str(fp.get("finding", "")), "why": str(fp.get("why", ""))}
        for fp in out.get("false_positives", []) if isinstance(fp, dict)
    ]
    result = {"fixes": fixes, "false_positives": fps}
    cache.set("fixes", ck, result)
    return result


@app.post("/report-fixes")
async def report_fixes(body: ReportBody):
    """Per-report prioritized fixes + likely false positives (for THIS report only)."""
    if not body.findings:
        return {"fixes": [], "false_positives": []}
    return await run_in_threadpool(_report_fixes, body.name, body.findings, body.focus)


class Findings(BaseModel):
    findings: List[dict] = []


@app.post("/correlate")
async def correlate_endpoint(body: Findings):
    """Cross-report correlation (only meaningful when reports share a target)."""
    if not body.findings:
        return {"correlation": {"related": False, "scope": "No findings to correlate.",
                                "confirmed": [], "hidden_risks": [], "common_fixes": []}}
    result = await run_in_threadpool(correlate, body.findings)
    # Guarantee the shape the frontend expects, even if the model returned junk.
    result.setdefault("related", False)
    result.setdefault("scope", "")
    for k in ("confirmed", "hidden_risks", "common_fixes"):
        if not isinstance(result.get(k), list):
            result[k] = []
    return {"correlation": result}


@app.post("/graph")
def graph_endpoint(body: Findings):
    """Attack-surface graph built FROM the uploaded findings (deterministic, no LLM)."""
    if not body.findings:
        return {"nodes": [], "edges": [], "paths": [], "assumptions": [],
                "reachable_critical": [], "critical_assets": []}
    return build_web_graph(body.findings)


class SimBody(BaseModel):
    nodes: List[dict] = []
    edges: List[dict] = []
    cut: List[str] = []


@app.post("/simulate")
def simulate_endpoint(body: SimBody):
    """What-if remediation: cut one (assumed) edge and recompute paths + reachability."""
    if len(body.cut) != 2:
        return {"error": "cut must be [source, target]"}
    return simulate_cut(body.nodes, body.edges, body.cut)
