# Sentinel — full project handoff (start → now)

Read this first if you're picking the project up fresh. It covers the whole story: how it
began, what was built in each phase, where it stands today, the goal, how to run it, and the
gotchas.

---

## 1. What Sentinel is (today)
A full-stack **security platform that tests both AI apps and web apps** and analyzes the results
with an LLM. Three scan types feed one findings → score → history pipeline:

1. **AI / LLM red-team** — an autonomous agent (RedCell, LangGraph) attacks a chatbot (its
   system prompt, *or* a live API endpoint) with jailbreak / prompt-injection / prompt-leak /
   data-extraction attacks; an LLM-as-judge scores each hit. **This is the headline differentiator.**
2. **Web app scan** — safe built-in checks (TLS/cert, HTTP security headers, open ports), plus
   optional **real external scanners** (Nmap, Nuclei, Wapiti, …) when self-hosted.
3. **Report upload** — ingest real scanner output (Nmap/Nessus/OpenVAS/ZAP/Wazuh/SSL),
   parsed deterministically, with an LLM fallback for unknown formats.

On top: a unified **security score (0–100)**, cross-scan **dashboard**, **attack-path graph**,
**MITRE ATT&CK** mapping, LLM **exec summary**, **red-team transcript**, PDF export, history,
and an **LLM-security guardrail** layer (defends Sentinel's own model from prompt injection in
the data it ingests; measured eval + threat model in `SECURITY.md`).

## 2. The goal
This is the owner's **flagship portfolio project**, built to demonstrate **AI-security
engineering** — both sides of the coin: **offense** (RedCell autonomously attacks LLMs) and
**defense** (guardrails + threat model) — alongside full-stack delivery. The immediate objective
is to **deploy it to a public URL** so it can be shared as a live demo. Guiding principle
throughout: **honest, defensible claims** — the tool clearly labels what's measured vs inferred
vs heuristic, and never overstates.

---

## 3. How it evolved (the whole journey)

**Origin — "AI Security Digital Twin" (milestones M1–M4).** Started as a tool that ingests
security reports and reasons about them:
- M1: attack-path engine (graph + risk scoring + dashboard).
- M2: Gemini "RAG brain" explaining attack paths.
- M3: what-if remediation simulation (which fix removes the most risk).
- M4: real Nmap / vuln-scanner / OWASP ZAP / Wazuh ingestion + version→CVE enrichment.
- Then: universal LLM report ingestion + cross-tool correlation; a full-stack web app;
  a reliability/correctness pass; and a speed pass (parallel pipelines, fast-model order, caching).

**Review & hardening era.** Multiple external code reviews were worked through honestly:
- Evidence-qualified attack graph (edges typed `exploit` vs `exposure`; paths labeled
  hypothetical vs vuln-backed vs topology-backed — never overclaimed).
- Deterministic parsers for known scanner formats (exact, no LLM).
- Interaction controls: cancel, per-stage timeout, elapsed timer, retry.
- History management: rename, tag, delete.
- Topology input → "confirmed" paths + control-specific remediation; topology template +
  one-click auto-suggest.
- Expanded red-team eval + detector; evidence-honest wording; mobile overflow fixes; favicon.

**Rebrand & design era.** Renamed **"AI Security Digital Twin" → "Sentinel Security"** (dropped
"Digital Twin"; wordmark settled on **SENTINEL**). Built a real **module rail + workspace**
("security-console" layout). Added **Dashboard, Compare, MITRE ATT&CK, AI Executive Summary**
modules. Many theme iterations (security-console → light → premium dashboard with risk gauge &
donut → collapsible rail → uniform surfaces). Added a built-in **automatic web scan**
(TLS/headers/ports). Deploy scaffolding added (Dockerfile, Render blueprint, DEPLOY.md).

**Honesty rigor pass.** README rewritten to be moderate/defensible; rigor on the LLM-security
core — detector eval split into **core vs adaptive** tiers (honest ~93% core / 0% adaptive, with
misses printed), a measured **naive-14% → hardened-0% attack-success-rate** delta, and a
one-page threat model (`SECURITY.md`).

**Platform build — Phases 1–6 (the big leap: report-analyzer → platform).** Decision: evolve
Sentinel into a unified platform combining AI red-teaming + web scanning, reusing the existing
FastAPI + Next.js stack (no rewrite), and integrating a *separate* already-built project called
**RedCell** (an autonomous LangGraph red-team agent) as the AI module.
- **Phase 1** — unify the scan model: every scan tagged `module` (ai|web|upload) + a shared
  **security score**, behind a swappable `ScanStore`.
- **Phase 2** — integrate RedCell into the backend as a **background job** (+ `/scans/ai`).
- **Phase 3** — AI red-team **UI**: form + live attack log + results.
- **Phase 4** — **Supabase Postgres** store (same `ScanStore` interface, SQLAlchemy).
- **Phase 5** — cross-scan **dashboard**, scores everywhere, honest platform docs.
- **Phase 6 (prep)** — deploy config.
- Plus **live-endpoint mode**: the red-team can attack a *real deployed chatbot API*, not just a
  simulated system prompt.

**Overhaul + QA + safety.** A full **dark "command-center" UI overhaul** + a scan **launcher
hub** (bold cards per scan type). A senior-tester QA pass fixed real bugs (two conflicting
scores → unified; an LLM feature that hung → fast model + timeout). Added an **abuse/cost guard**
(per-IP rate limiting, optional `SENTINEL_ACCESS_CODE` gate, SSRF protection), a **red-team
transcript** view (every attack→response→verdict), and plain-language **hints on every input**.

**Real external tools.** Added a real-scanner suite in `tool_scan.py`
(**nmap/nuclei/nikto/sslscan/wapiti/whatweb/testssl**): run any combination or a **"Full scan —
all tools"** against one URL, merged + de-duped. Gated (`ENABLE_LIVE_TOOLS=1`), SSRF-guarded,
rate-limited; not-installed tools show as **"coming soon."** Also fixed the built-in scan to
tolerate bad certs and fall back https→http.

---

## 4. Where we are **right now**
- **Feature-complete and polished.** Runs locally. **All code committed + pushed to `main`.**
- **NOT deployed** — there is no public URL yet. (This is the main thing left.)
- The built-in web scan and **both** AI red-team modes (simulated + live-endpoint) work without
  any external tools.
- **Real tools install state (current dev machine = Windows):**
  - ✅ **Wapiti** — installed (`pip install wapiti3`) and **verified working** (3 findings on example.com).
  - ⚠️ **Nuclei** — binary installed (`~/sentinel-tools/nuclei.exe`, on user PATH) but its
    **templates didn't download** (network/GitHub block) → finds nothing until fixed:
    `git clone https://github.com/projectdiscovery/nuclei-templates "%USERPROFILE%\nuclei-templates"`.
  - ❌ **Nmap** — needs admin (Npcap) → not installed; official installer enables it.
  - ❌ **Nikto / WhatWeb / sslscan / testssl** — need Perl/Ruby/bash → easiest on Linux (WSL/deploy).

## 5. What's next (priority order)
1. **Deploy** — backend on **Railway**, frontend on **Vercel** (optional: Supabase for the DB,
   `SENTINEL_ACCESS_CODE` to gate it). The `Dockerfile` respects `$PORT`; see `DEPLOY.md`.
   **This produces the shareable live link and is the #1 priority.**
2. Clean the demo history before showing it publicly.
3. (Optional) Finish Nuclei templates; add Nmap; run the full 7-tool suite on Linux.
4. (Roadmap) auth/multi-user, scheduled scans, CI/ticketing integrations, richer attack corpora.

---

## 6. Architecture & file map
- **Backend:** FastAPI (`api.py`), Python 3.11; blocking LLM calls via `run_in_threadpool`;
  long scans as in-memory background jobs (`jobs.py`).
- **Frontend:** Next.js (App Router, JS) — essentially one file `frontend/app/page.js` +
  `frontend/app/globals.css` (dark design system).
- **LLM:** Google Gemini via `llm.py` (multi-model fallback + cache).
- **Store:** `store.py` (`ScanStore`: disk default, Postgres via `db.py` when a DB URL is set).

```
api.py              FastAPI: /extract /scan /scans/ai /tools /scan-tool /correlate /graph
                    /simulate /exec-summary /export-report /runs  + abuse-guard middleware
llm.py              Gemini chat + model fallback + cache
guardrails.py       L1 detect / L2 harden / L3 output-check (prompt-injection defense)
redteam_eval*.py    L4 evals (detector recall/FP; naive-vs-hardened attack-success-rate)
scoring.py          deterministic 0-100 security score (shared everywhere)
store.py / db.py    persistence (disk + Postgres/Supabase, swappable)
live_scan.py        built-in lightweight web scan (TLS/headers/ports, stdlib only)
tool_scan.py        REAL external scanners (nmap/nuclei/nikto/sslscan/wapiti/whatweb/testssl)
redcell/            vendored autonomous red-team agent (agent/attacks/judge/llm/models)
ai_scan.py          runs RedCell as a job, maps report -> findings, captures transcript
jobs.py             in-memory background-job registry
target_client.py    live-endpoint caller for AI red-team + SSRF guard
correlate.py        cross-tool correlation
web_graph.py        attack-surface graph + what-if simulation
report_export.py    PDF export (fpdf2)
frontend/app/page.js  the entire UI (rail, dashboard, scan flows, result views)
```

## 7. How to run locally
Backend (from `Sentinal/`, Python 3.11):
```
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
# .env:  GEMINI_API_KEY=...   (optional: REDCELL_GEMINI_KEY, DATABASE_URL, SENTINEL_ACCESS_CODE)
python -m uvicorn api:app --host 0.0.0.0 --port 8000
```
Frontend (from `Sentinal/frontend/`, Node 18+): `npm install && npm run dev` → http://localhost:3000
Security evals: `python redteam_eval.py` and `python redteam_eval_e2e.py`.

### Env flags
- `GEMINI_API_KEY` (required) · `REDCELL_GEMINI_KEY` (dedicated red-team key)
- `DATABASE_URL` / `SUPABASE_DB_URL` → Postgres store
- `SENTINEL_ACCESS_CODE` → require `X-Access-Code` header (gate a public deploy)
- `ENABLE_LIVE_TOOLS=1` → enable real external scanners (off by default)
- `SENTINEL_ALLOW_PRIVATE_TARGETS=1` → allow localhost/private targets (local lab only)

## 8. Gotchas
- **`pip install wapiti3` breaks the backend** — it downgrades `typing_extensions`/`asgiref` and
  pydantic fails. Repair: `pip install -U "typing_extensions>=4.12.2" "asgiref>=3.8"` (both work after).
- The in-app dev browser can show **stale console errors** — verify in a fresh tab.
- Gemini free-tier is slow/throttled; heavy models hang, so `exec-summary` uses the fast
  (lite-first) order + a 60s frontend timeout. `correlate` and AI scans can take a minute+.
- In-memory jobs are lost on backend restart (fine for single instance; not horizontally scalable).
- Real scanners must stay **off on any public deploy** (a public scanner = abuse/legal risk).
