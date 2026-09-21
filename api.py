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
from live_scan import run_web_scan
from store import get_store, new_id
import scoring
from report_export import build_pdf
from llm import call_llm, FAST_MODELS, GEMINI_MODELS

APP_VERSION = "0.5"
RUNS_DIR = os.path.join(os.path.dirname(__file__), "runs")
os.makedirs(RUNS_DIR, exist_ok=True)

app = FastAPI(title="Sentinel Security API")
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


class ScanBody(BaseModel):
    target: str = ""
    ports: bool = True


@app.post("/scan")
async def scan(body: ScanBody):
    """Automatic scan: run a light, non-intrusive live assessment of ONE authorized web
    target (TLS + security headers + common-port reachability) and return a report-shaped
    result whose findings flow into the same pipeline as uploaded reports.

    The caller is responsible for target authorization (enforced in the UI)."""
    target = (body.target or "").strip()
    if not target:
        return {"name": "", "host": "", "findings": [], "sha256": None,
                "parser": "live:web", "security": None, "scan": None,
                "error": "No target provided."}
    try:
        result = await run_in_threadpool(run_web_scan, target, body.ports)
    except ValueError as e:
        return {"name": target, "host": "", "findings": [], "sha256": None,
                "parser": "live:web", "security": None, "scan": None,
                "error": f"Invalid target: {e}"}
    except Exception as e:
        return {"name": target, "host": "", "findings": [], "sha256": None,
                "parser": "live:web", "security": None, "scan": None,
                "error": f"Scan failed: {e}"}

    # Provenance: hash the normalized target + a coarse timestamp so runs are identifiable.
    stamp = f"{result['host']}@{int(time.time())}"
    return {
        "name": result["name"], "host": result["host"], "findings": result["findings"],
        "sha256": hashlib.sha256(stamp.encode()).hexdigest(),
        "parser": "live:web", "security": None, "scan": result["scan"], "error": None,
    }


class AIScanBody(BaseModel):
    system_prompt: str = ""       # simulated mode: the target's own rules (what we red-team)
    target_name: str = "Target LLM app"
    categories: List[str] = []    # empty = all attack categories
    budget: int = 12              # max total attacks
    max_per_category: int = 2
    authorized: bool = False      # user must confirm they own/may test the target
    target_mode: str = "simulated"        # simulated | endpoint
    endpoint: Optional[dict] = None       # endpoint mode: {url, preset, api_key, model, headers, body_template, response_path}
    target_rules: str = ""                # endpoint mode: optional description of the bot's rules (for the judge)


@app.post("/scans/ai")
def start_ai_scan(body: AIScanBody):
    """Start an autonomous AI/LLM red-team scan (RedCell) as a background job.

    Two target modes:
      - simulated: attack a system prompt the user supplies (run on our own model);
      - endpoint:  black-box attack a LIVE chatbot API URL the user supplies.
    Returns a job id immediately; poll GET /scans/ai/{id} for live progress + result."""
    import jobs
    from ai_scan import run_ai_scan
    if not body.authorized:
        return {"error": "Confirm you're authorized to test this target."}

    endpoint = None
    if body.target_mode == "endpoint":
        endpoint = body.endpoint or {}
        if not (endpoint.get("url") or "").strip():
            return {"error": "Provide the live chatbot API URL to test."}
        from target_client import guard_url, TargetError
        try:
            guard_url(endpoint["url"])                # fail fast on a blocked/invalid URL (SSRF guard)
        except TargetError as e:
            return {"error": str(e)}
    else:
        if not body.system_prompt.strip():
            return {"error": "Provide the target LLM app's system prompt to red-team."}

    budget = max(1, min(body.budget, 30))            # keep runs bounded
    max_per = max(1, min(body.max_per_category, 5))
    jid = jobs.create("ai", body.target_name)
    jobs.run_in_thread(run_ai_scan, jid, body.system_prompt, body.target_name,
                       body.categories, budget, max_per, endpoint, body.target_rules)
    return {"job_id": jid}


@app.get("/scans/ai/{job_id}")
def ai_scan_status(job_id: str):
    """Poll an AI red-team job: status (running|done|error), live log, progress, result."""
    import jobs
    j = jobs.get(job_id)
    return j if j is not None else {"error": "not found"}


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


class SummaryBody(BaseModel):
    reports: List[dict] = []
    correlation: Optional[dict] = None
    graph: Optional[dict] = None


def _exec_summary(reports, correlation, graph):
    findings = [f for r in reports for f in (r.get("findings") or [])]
    sev = {}
    for f in findings:
        s = f.get("severity", "Unknown")
        sev[s] = sev.get(s, 0) + 1
    paths = (graph or {}).get("paths", [])
    ctx = {
        "reports": [r.get("name") for r in reports],
        "finding_count": len(findings),
        "severity_counts": sev,
        "top_findings": [f"{f.get('severity')}: {f.get('name')} @ {f.get('host')}" for f in findings[:12]],
        "attack_paths": [{"path": " -> ".join(p.get("path", [])), "class": p.get("path_class"),
                          "likelihood": p.get("likelihood")} for p in paths[:5]],
        "topology_supplied": (graph or {}).get("topology_supplied", False),
        "injection_reports": [r.get("name") for r in reports if (r.get("security") or {}).get("injection_detected")],
        "correlation_related": (correlation or {}).get("related", False),
    }
    system = guardrails.INJECTION_DEFENSE + (
        "You are a senior security analyst writing a concise EXECUTIVE SUMMARY for a technical "
        "manager, using ONLY the analysis JSON. Structure with these headings: 'Risk posture:' "
        "(one line), 'Key findings:' (3-5 short '- ' bullets), 'Recommended actions:' (3-5 "
        "prioritized '- ' bullets). Be specific and HONEST: attack paths are hypothetical unless "
        "topology was supplied; never claim exploitation, breach, or compromise. Keep it under ~200 words."
    )
    user = "ANALYSIS (JSON):\n" + json.dumps(ctx, indent=2)
    return call_llm(system, user)


@app.post("/exec-summary")
async def exec_summary(body: SummaryBody):
    """LLM-written executive summary of the analysis (honest about hypothetical paths)."""
    if not body.reports:
        return {"summary": ""}
    text = await run_in_threadpool(_exec_summary, body.reports, body.correlation, body.graph)
    return {"summary": (text or "").strip()}


class RunBody(BaseModel):
    reports: List[dict] = []
    correlation: Optional[dict] = None
    graph: Optional[dict] = None
    exec_summary: str = ""
    module: str = "upload"          # ai | web | upload — which scan produced this
    target: str = ""               # the scanned target/URL/host or uploaded file names


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
    all_findings = [f for r in reports for f in (r.get("findings") or [])]
    sc = scoring.score_findings(all_findings, graph)
    return {
        "created": time.time(),
        "module": data.get("module", "upload"),
        "target": data.get("target", ""),
        "score": sc["score"],
        "band": sc["band"],
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


def _summary_score(d):
    """Score for a saved scan - prefer the stored value, else compute (legacy runs)."""
    meta = d.get("meta") or {}
    if isinstance(meta.get("score"), int):
        return meta["score"], meta.get("band", scoring.band(meta["score"]))
    all_findings = [f for r in (d.get("reports") or []) for f in (r.get("findings") or [])]
    sc = scoring.score_findings(all_findings, d.get("graph"))
    return sc["score"], sc["band"]


@app.post("/runs")
def save_run(body: RunBody):
    """Persist one scan (with provenance + score) so it can be reloaded later."""
    data = body.model_dump()
    data["_id"], data["_created"] = new_id(), time.time()
    data["meta"] = _build_meta(data)
    data["score"] = data["meta"]["score"]  # top-level for quick access
    sid = get_store().save(data)
    return {"id": sid, "meta": data["meta"]}


@app.get("/runs")
def list_runs():
    """List saved scans (newest first) with a short summary each - incl. module + score."""
    out = []
    for d in get_store().list(limit=100):
        reports = d.get("reports", []) or []
        score, band = _summary_score(d)
        meta = d.get("meta") or {}
        sev = {}
        for r in reports:
            for f in (r.get("findings") or []):
                k = str(f.get("severity", "Unknown")).title()
                sev[k] = sev.get(k, 0) + 1
        out.append({
            "id": d.get("_id"), "created": d.get("_created"),
            "label": d.get("label"), "tag": d.get("tag"),
            "module": meta.get("module", d.get("module", "upload")),
            "target": meta.get("target", d.get("target", "")),
            "score": score, "band": band, "severity": sev,
            "reports": len(reports),
            "findings": sum(len(r.get("findings", []) or []) for r in reports),
            "names": [r.get("name") for r in reports][:4],
        })
    return {"runs": out}


@app.get("/runs/{run_id}")
def get_run(run_id: str):
    """Load one saved scan by id."""
    d = get_store().get(run_id)
    return d if d is not None else {"error": "not found"}


class RunUpdate(BaseModel):
    label: Optional[str] = None
    tag: Optional[str] = None


@app.post("/runs/{run_id}/update")
def update_run(run_id: str, body: RunUpdate):
    """Rename (label) or tag a saved scan."""
    fields = {}
    if body.label is not None:
        fields["label"] = body.label[:80]
    if body.tag is not None:
        fields["tag"] = body.tag[:24]
    ok = get_store().update(run_id, fields)
    return {"ok": True} if ok else {"error": "not found"}


@app.delete("/runs/{run_id}")
def delete_run(run_id: str):
    """Delete a saved scan."""
    get_store().delete(run_id)
    return {"ok": True}
