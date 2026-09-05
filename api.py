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

import hashlib
import io
import json
import os
import time
import uuid
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from universal_ingest import extract_findings
from deterministic_ingest import parse_deterministic
from correlate import correlate
import cache
import guardrails
from web_graph import build_web_graph, simulate_cut
from report_export import build_pdf
from llm import call_llm, FAST_MODELS, GEMINI_MODELS

APP_VERSION = "0.5"
RUNS_DIR = os.path.join(os.path.dirname(__file__), "runs")
os.makedirs(RUNS_DIR, exist_ok=True)

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
    sha256 = hashlib.sha256(raw).hexdigest()  # provenance: which exact file was analyzed
    text = read_report(raw, file.filename)
    if len(text.strip()) < 30:
        return {
            "name": file.filename, "findings": [], "sha256": sha256, "parser": None,
            "error": "Could not extract readable text (possibly a scanned / image-only PDF, "
                     "an empty file, or an unsupported binary format).",
        }
    # Layer 1 (detect): scan the untrusted report for prompt-injection (runs regardless).
    security = guardrails.summarize(guardrails.scan_injection(text))

    # Deterministic first: for KNOWN formats we parse structured fields - instant, ground-truth,
    # and immune to injection (no LLM prompt is built from the report). Fall back to the LLM parser.
    det_findings, fmt = parse_deterministic(text, file.filename)
    if det_findings is not None:
        findings = det_findings
        parser = f"deterministic:{fmt}"
        security["output_ok"] = True
        security["output_reason"] = "no LLM used for extraction (deterministic parser)"
    else:
        # Blocking LLM work runs in a worker thread; extraction is hardened (L2) + output-checked (L3).
        findings, out_check = await run_in_threadpool(extract_findings, text, file.filename, True)
        parser = "llm"
        security["output_ok"] = out_check.get("ok", True)
        security["output_reason"] = out_check.get("reason", "")

    return {"name": file.filename, "findings": findings, "sha256": sha256,
            "error": None, "security": security, "parser": parser}


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
    topology: Optional[dict] = None  # optional user-supplied connections (used by /graph)


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
    if "corroborated" not in result and "confirmed" in result:  # tolerate old key
        result["corroborated"] = result.pop("confirmed")
    for k in ("corroborated", "hidden_risks", "common_fixes"):
        if not isinstance(result.get(k), list):
            result[k] = []
    return {"correlation": result}


@app.post("/graph")
def graph_endpoint(body: Findings):
    """Attack-surface graph built FROM the uploaded findings, optionally using a user-supplied
    topology (deterministic, no LLM)."""
    if not body.findings:
        return {"nodes": [], "edges": [], "paths": [], "assumptions": [],
                "reachable_critical": [], "critical_assets": [], "topology_supplied": False}
    return build_web_graph(body.findings, body.topology)


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


class RunBody(BaseModel):
    reports: List[dict] = []
    correlation: Optional[dict] = None
    graph: Optional[dict] = None


@app.post("/export-report")
def export_report(body: RunBody):
    """Render the full analysis to a downloadable PDF."""
    pdf = build_pdf(body.model_dump())
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="sentinel-report.pdf"'})


def _build_meta(data):
    """Provenance for a saved analysis - so a restored run is self-describing and auditable."""
    reports = data.get("reports", []) or []
    graph = data.get("graph") or {}
    assumed = any(e.get("assumed") for e in (graph.get("edges") or []))
    return {
        "created": time.time(),
        "model": "Gemini (per-call fallback across the flash family)",
        "model_chain": GEMINI_MODELS,
        "app_version": APP_VERSION,
        "scoring_version": graph.get("scoring_version", "n/a"),
        "topology": "inferred" if assumed else ("supplied" if graph else "n/a"),
        "files": [
            {
                "name": r.get("name"),
                "sha256": r.get("sha256"),
                "parser": r.get("parser"),
                "findings": len(r.get("findings", []) or []),
                # did the guardrails actually run on this report?
                "security_evaluated": isinstance((r.get("security") or {}).get("injection_detected"), bool),
            }
            for r in reports
        ],
    }


@app.post("/runs")
def save_run(body: RunBody):
    """Persist one analysis (with provenance) so it can be reloaded later."""
    rid = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    data = body.model_dump()
    data["_id"], data["_created"] = rid, time.time()
    data["meta"] = _build_meta(data)
    with open(os.path.join(RUNS_DIR, rid + ".json"), "w", encoding="utf-8") as f:
        json.dump(data, f)
    return {"id": rid, "meta": data["meta"]}


@app.get("/runs")
def list_runs():
    """List saved analyses (newest first) with a short summary each."""
    out = []
    for fn in sorted(os.listdir(RUNS_DIR), reverse=True):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(RUNS_DIR, fn), encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            continue
        reports = d.get("reports", []) or []
        out.append({
            "id": d.get("_id", fn[:-5]), "created": d.get("_created"),
            "label": d.get("label"), "tag": d.get("tag"),
            "reports": len(reports),
            "findings": sum(len(r.get("findings", []) or []) for r in reports),
            "names": [r.get("name") for r in reports][:4],
        })
    return {"runs": out[:100]}


@app.get("/runs/{run_id}")
def get_run(run_id: str):
    """Load one saved analysis by id."""
    safe = os.path.basename(run_id)  # prevent path traversal
    p = os.path.join(RUNS_DIR, safe + ".json")
    if not os.path.exists(p):
        return {"error": "not found"}
    with open(p, encoding="utf-8") as f:
        return json.load(f)


class RunUpdate(BaseModel):
    label: Optional[str] = None
    tag: Optional[str] = None


@app.post("/runs/{run_id}/update")
def update_run(run_id: str, body: RunUpdate):
    """Rename (label) or tag a saved run."""
    safe = os.path.basename(run_id)
    p = os.path.join(RUNS_DIR, safe + ".json")
    if not os.path.exists(p):
        return {"error": "not found"}
    with open(p, encoding="utf-8") as f:
        d = json.load(f)
    if body.label is not None:
        d["label"] = body.label[:80]
    if body.tag is not None:
        d["tag"] = body.tag[:24]
    with open(p, "w", encoding="utf-8") as f:
        json.dump(d, f)
    return {"ok": True}


@app.delete("/runs/{run_id}")
def delete_run(run_id: str):
    """Delete a saved run."""
    safe = os.path.basename(run_id)
    p = os.path.join(RUNS_DIR, safe + ".json")
    if os.path.exists(p):
        try:
            os.remove(p)
        except Exception as e:
            return {"error": str(e)}
    return {"ok": True}
