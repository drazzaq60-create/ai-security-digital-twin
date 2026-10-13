# tool_report.py
# Turns a multi-tool web scan (findings + each tool's full raw output) into ONE
# comprehensive, professional security report, written by the LLM.
#
# The raw tool output is UNTRUSTED (it contains whatever the target returned — banners,
# page bodies, headers — which an attacker controls), so it is wrapped with the same
# injection-defence preamble + delimiters the report-upload path uses (guardrails L2).

import json

import guardrails
from llm import call_llm, GEMINI_MODELS

# Keep each tool's raw output bounded so a huge scan doesn't blow the context window.
_MAX_RAW_PER_TOOL = 6000
_MAX_FINDINGS = 200


def _clip(text, n):
    text = text or ""
    return text if len(text) <= n else text[:n] + f"\n…[truncated, {len(text) - n} more chars]"


def build_comprehensive_report(target, tools_ran, findings, raw_by_tool, failed_tools):
    """Return a Markdown report string. Raises if the LLM is unavailable (no API key, etc.);
    the caller logs that and still returns the structured findings."""
    sev_counts = {}
    for f in findings:
        s = str(f.get("severity", "Unknown")).title()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # Compact, structured context for the model. Findings are our parsed/normalised view;
    # raw is the ground truth each tool emitted (so the model can extract detail the terse
    # parsers dropped).
    ctx = {
        "target": target,
        "tools_run": tools_ran,
        "tools_failed": failed_tools,
        "finding_count": len(findings),
        "severity_counts": sev_counts,
        "findings": [
            {k: f.get(k) for k in ("name", "severity", "type", "host", "evidence", "source")}
            for f in findings[:_MAX_FINDINGS]
        ],
    }
    raw_blocks = []
    for r in raw_by_tool:
        head = f"### {r.get('tool_name')} (exit {r.get('returncode')}, {'ok' if r.get('ok') else 'FAILED'})"
        if not r.get("ok") and r.get("note"):
            head += f"\nerror: {r['note']}"
        raw_blocks.append(head + "\n" + _clip(r.get("raw", "") or "(no output)", _MAX_RAW_PER_TOOL))
    raw_text = "\n\n".join(raw_blocks)

    system = guardrails.INJECTION_DEFENSE + (
        "You are a senior penetration tester writing the final report for an authorised web "
        "security assessment. You are given (a) normalised FINDINGS extracted from the tools and "
        "(b) each tool's RAW OUTPUT. Write ONE complete, professional report in GitHub-flavoured "
        "Markdown with EXACTLY these sections and headings:\n"
        "# Security Assessment Report\n"
        "## Executive Summary  — 2-4 sentences on overall posture for a non-technical reader.\n"
        "## Risk Rating  — one of Critical/High/Medium/Low/Informational, with a one-line justification.\n"
        "## Scope & Methodology  — the target, the tools run, and (if any) tools that FAILED to run "
        "(call those out explicitly — their areas were NOT assessed).\n"
        "## Key Findings  — a Markdown table: | Severity | Finding | Affected | Evidence |. "
        "Consolidate duplicates reported by multiple tools and note when tools corroborate each other. "
        "Order by severity (Critical first).\n"
        "## Detailed Analysis  — for each notable finding: what it is, why it matters, realistic impact, "
        "and how it could be exploited. Pull concrete details (versions, paths, ports, headers) from the "
        "RAW OUTPUT, not just the finding titles.\n"
        "## Attack Surface & Exploitation Paths  — how the findings could chain; be explicit that chaining "
        "is hypothetical unless evidenced.\n"
        "## Remediation Roadmap  — prioritised, numbered, most impactful first; concrete and actionable.\n\n"
        "RULES: Base everything ONLY on the provided data. Never invent findings, hosts, CVEs or versions "
        "not present in the data. If the data is thin, say so honestly rather than padding. If no real "
        "issues were found, say the target looked healthy for the checks performed. Do not claim "
        "exploitation was performed — these are detection-stage findings. Be specific and technical but clear."
    )
    user = (
        "SCAN CONTEXT (JSON):\n" + json.dumps(ctx, indent=2) + "\n\n"
        + guardrails.harden_prompt(raw_text, label="RAW TOOL OUTPUT")
    )
    # Capable models first (this is the headline deliverable, not a quick structured task).
    text = call_llm(system, user, temperature=0.2, models=GEMINI_MODELS)
    out = (text or "").strip()
    if not out:
        raise RuntimeError("model returned an empty report")
    return out
