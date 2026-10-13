# Sentinel — project status & developer handoff

A snapshot of what's built, how to run it, what's next, and the gotchas. Read this first if
you're picking the project up fresh.

---

## What Sentinel is
A full-stack security platform that tests **both AI apps and web apps** and analyzes the
results with an LLM. Three scan types feed one findings → score → history pipeline:

1. **AI / LLM red-team** — an autonomous agent (RedCell, LangGraph) attacks a chatbot
   (its system prompt, *or* a live API endpoint) with jailbreak / injection / prompt-leak /
   data-extraction attacks; an LLM-as-judge scores each hit. (The headline differentiator.)
2. **Web app scan** — safe built-in checks (TLS/cert, HTTP security headers, open ports), and
   optionally **real external scanners** (Nmap, Nuclei, Wapiti, …) when self-hosted.
3. **Report upload** — ingest real scanner output (Nmap/Nessus/OpenVAS/ZAP/Wazuh/SSL),
   parsed deterministically, LLM fallback for unknown formats.

On top: a **unified security score (0–100)**, cross-scan **dashboard**, **attack-path graph**,
**MITRE ATT&CK** mapping, LLM **exec summary**, **red-team transcript**, PDF export, history,
and an **LLM-security guardrail** layer that protects Sentinel's own model from prompt injection
in the data it ingests (with a measured red-team eval + threat model in `SECURITY.md`).

---

## Tech & architecture
- **Backend:** FastAPI (`api.py`), Python 3.11. Blocking LLM calls run in `run_in_threadpool`;
  long scans run as in-memory background jobs (`jobs.py`).
- **Frontend:** Next.js (App Router, JS), single main file `frontend/app/page.js` +
  `frontend/app/globals.css` (dark "command-center" design system).
- **LLM:** Google Gemini via `llm.py` (multi-model fallback + cache). RedCell uses its own key.
- **Store:** `store.py` — swappable `ScanStore`; disk by default, **Postgres/Supabase** when
  `DATABASE_URL`/`SUPABASE_DB_URL` is set (`db.py`, SQLAlchemy).

### Key files
```
api.py              FastAPI app: /extract /scan /scans/ai /tools /scan-tool /correlate /graph
                    /simulate /exec-summary /export-report /runs ; abuse-guard middleware
llm.py              Gemini chat + fallback + cache
guardrails.py       L1 detect / L2 harden / L3 output-check (prompt-injection defense)
redteam_eval*.py    L4 evals (detector recall/FP; naive-vs-hardened ASR)
scoring.py          deterministic 0-100 security score
store.py / db.py    persistence (disk + Postgres)
live_scan.py        built-in lightweight web scan (TLS/headers/ports, stdlib only)
tool_scan.py        REAL external scanners (nmap/nuclei/nikto/sslscan/wapiti/whatweb/testssl)
redcell/            vendored autonomous red-team agent (agent/attacks/judge/llm/models)
ai_scan.py          runs RedCell as a job, maps report -> findings, captures transcript
jobs.py             in-memory background-job registry
target_client.py    live-endpoint caller for AI red-team + SSRF guard
correlate.py        cross-tool correlation
web_graph.py        attack-surface graph + what-if simulation
report_export.py    PDF export
frontend/app/page.js  entire UI (rail, dashboard, scan flows, results views)
```

---

## How to run locally
**Backend** (Python 3.11), from `Sentinal/`:
```
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
# .env:  GEMINI_API_KEY=...   (optional: REDCELL_GEMINI_KEY, DATABASE_URL, SENTINEL_ACCESS_CODE)
python -m uvicorn api:app --host 0.0.0.0 --port 8000
```
**Frontend** (Node 18+), from `Sentinal/frontend/`:
```
npm install && npm run dev        # http://localhost:3000
```
Run the security evals: `python redteam_eval.py` and `python redteam_eval_e2e.py`.

### Env flags
- `GEMINI_API_KEY` — required. `REDCELL_GEMINI_KEY` — optional dedicated key for the red-team.
- `DATABASE_URL` / `SUPABASE_DB_URL` — switch the store to Postgres.
- `SENTINEL_ACCESS_CODE` — require an `X-Access-Code` header (gate a public deploy).
- `ENABLE_LIVE_TOOLS=1` — enable the real external scanners (see below). Off by default.
- `SENTINEL_ALLOW_PRIVATE_TARGETS=1` — allow localhost/private targets (local lab only).

---

## Real external tools (Web scan)
Implemented in `tool_scan.py`: **nmap, nuclei, nikto, sslscan, wapiti, whatweb, testssl**.
Gated hard: only run when `ENABLE_LIVE_TOOLS=1`, only installed tools are offered, targets are
SSRF-guarded + rate-limited, each run is timed out. The Web-scan "Scan engine" picker lets you
choose any combination or "Full scan — all tools"; not-installed tools show as **"coming soon."**

**Install state (current dev machine = Windows):**
- ✅ **Wapiti** — installed (`pip install wapiti3`), verified working (found 3 findings on example.com).
- ⚠️ **Nuclei** — binary installed (`~/sentinel-tools/nuclei.exe`, on user PATH) BUT its
  **templates did not download** (network/GitHub block) → finds nothing until fixed. To fix:
  `git clone https://github.com/projectdiscovery/nuclei-templates "%USERPROFILE%\nuclei-templates"`
  then re-scan.
- ❌ **Nmap** — needs admin (Npcap) on Windows → not installed; run the official installer to enable.
- ❌ **Nikto / WhatWeb / sslscan / testssl** — need Perl / Ruby / bash → easiest on Linux (WSL / deploy).

**⚠️ Dependency gotcha:** `pip install wapiti3` downgrades `typing_extensions`/`asgiref` and
breaks the backend's pydantic. Repair with:
`pip install -U "typing_extensions>=4.12.2" "asgiref>=3.8"` (backend + wapiti both work after).

---

## Current overall state
- Feature-complete and polished; runs locally; all code committed + pushed to `main`.
- **Not yet deployed** — there is no public URL.
- The built-in web scan + both AI red-team modes work without any external tools.

## What's next (priority order)
1. **Deploy** → backend on **Railway**, frontend on **Vercel** (optionally Supabase for the DB
   and `SENTINEL_ACCESS_CODE` to gate it). The `Dockerfile` respects `$PORT`. See `DEPLOY.md`.
   This produces the shareable link and is the top priority.
2. Clean demo history before showing it publicly.
3. (Optional) Finish Nuclei templates; add Nmap (admin installer); run the full 7-tool suite on Linux.
4. (Roadmap) auth/multi-user, scheduled scans, CI/ticketing integrations, richer AI-attack corpora.

## Gotchas worth knowing
- The in-app dev browser sometimes shows **stale console errors** — verify in a fresh tab.
- Gemini free-tier can be slow/throttled; heavy models hang, so `exec-summary` uses the fast
  (lite-first) model order and the frontend adds a 60s timeout.
- In-memory jobs are lost on backend restart (fine for single-instance; not horizontally scalable).
- Real scanners must stay **off on any public deploy** (a public scanner = abuse/legal risk).
