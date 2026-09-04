# 🛡️ AI Security Digital Twin & Attack-Path Reasoning Engine

An AI-assisted defensive security platform that models an environment as a **security graph**, discovers **multi-step attack paths** to critical assets, explains them with a **grounded, citation-backed LLM**, and **simulates remediations** to quantify which single fix removes the most risk.

> **The core idea:** a scary vulnerability on an isolated machine matters less than a medium one that creates a *path* from the internet to your database. This tool ranks fixes by **attack-path reduction**, not just severity score.

---

## Why it's different

- Not a chatbot, not a scanner, not an autonomous hacking tool.
- **Deterministic security logic** computes the facts (what connects to what, which paths exist); the **LLM only explains and recommends** — grounded in a knowledge base, with citations, and it refuses to answer outside its knowledge (no hallucination).
- Includes a **research finding**: ranking fixes by attack-path impact beats CVSS-severity-only prioritization (demonstrated below).

## What it does (current: M1–M3)

- **Attack-path engine** — models assets/services/vulnerabilities as a directed graph and finds every route from an exposed node to a critical asset, scored by cumulative risk × asset criticality.
- **RAG brain** — retrieves from a curated security knowledge base (OWASP / MITRE / CVE notes) using Gemini embeddings + a Chroma vector store, and answers **only** from retrieved sources, with citations.
- **AI attack-path analysis** — explains how an attacker would traverse a discovered path and recommends the single most effective fix.
- **What-if remediation simulation** — removes a vulnerability, recomputes the graph, and shows before/after attack-surface reduction; ranks all fixes by impact.
- **Interactive dashboard** (Streamlit) — visual graph, discovered paths, and a live remediation simulator.

### The key insight, proven with numbers
In the demo environment, *"Excessive DB permissions"* is the highest-severity single vulnerability (9), yet fixing the **lower-severity outdated CMS (6)** removes far more risk — because every attack path passes through it. A severity-only tool would pick the wrong fix; this one ranks by attack-path reduction and gets it right.

## Architecture

```
Environment (assets, services, vulnerabilities)
        -> Security Graph (networkx)
        -> Attack-Path Engine  (deterministic: find + score paths)
        -> RAG Brain (Gemini embeddings + Chroma retrieval)
        -> LLM Reasoning (Gemini, grounded + cited)  ->  explanation + recommended fix
        -> What-If Simulation  ->  before/after attack-surface reduction
```

## Tech stack

Python · networkx · ChromaDB · Google Gemini (chat + embeddings, with multi-model fallback) · Streamlit · Matplotlib

## Run it locally

```bash
python -m venv venv
venv\Scripts\Activate.ps1        # Windows PowerShell
pip install -r requirements.txt
```

Create a `.env` file with your Gemini key (free at aistudio.google.com):
```
GEMINI_API_KEY=your_key_here
```

Then:
```bash
streamlit run dashboard.py       # the visual dashboard (graph + paths + simulator)
python analyze.py                # AI explanation of the top attack path (needs the key)
python rag_engine.py             # test the grounded RAG brain (needs the key)
```

## Roadmap

- **M4** — real scanner ingestion (Nmap/vuln-scanner output), PostgreSQL + Neo4j, FastAPI, Docker
- **M5** — controlled investigation agent + guardrails (prompt-injection defense) + evaluation harness
- **M6** — auth/RBAC, CI/CD, deployment, observability
- **M7** — optional ML risk-ranking layer

## Responsible use

Built for **authorized, defensive** use only. All demonstrations use **synthetic/sanitized** data. No real or confidential organizational systems, logs, or credentials are used.
