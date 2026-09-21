# ai_scan.py
# Orchestrates an AI/LLM red-team scan for the Sentinel platform:
#   1. runs the RedCell LangGraph agent (streamed, so the UI gets a live attack log),
#   2. maps its RedTeamReport into Sentinel's universal finding shape,
#   3. scores it and persists it as an `ai` scan via the shared store.
#
# Kept separate from api.py so the endpoints stay thin.

import time

import jobs
import scoring
from store import get_store, new_id
from redcell.agent import build_agent
from redcell.attacks import ATTACK_LIBRARY
from redcell.models import AttackCategory

APP_VERSION = "0.6"


def parse_categories(names):
    """['prompt_injection', ...] -> [AttackCategory]. Empty/invalid -> all categories."""
    if not names:
        return list(ATTACK_LIBRARY.keys())
    out = []
    for n in names:
        try:
            out.append(AttackCategory(str(n)))
        except ValueError:
            continue
    return out or list(ATTACK_LIBRARY.keys())


def _map_report(report, target_name):
    """RedTeamReport -> a Sentinel 'report' object (same shape uploads/web scans produce)."""
    findings = []
    for f in report.findings:
        sev = f.severity.value
        sev = "Info" if sev == "None" else sev  # Sentinel has no 'None' severity band
        findings.append({
            "name": f.technique or f.category.value,
            "host": target_name,                     # group AI findings under the target app
            "severity": sev,
            "type": "ai:" + f.category.value,
            "evidence": f"Attack prompt: {f.example_prompt[:220]}\n\nTarget response: {f.evidence}",
            "source": "ai:redteam",
        })
    fixes = list(dict.fromkeys(f.recommendation for f in report.findings if f.recommendation))
    return {
        "name": f"AI red-team: {target_name}",
        "findings": findings,
        "fixes": fixes,
        "false_positives": [],
        "security": None,
        "parser": "ai:redteam",
        "scan": {
            "target": target_name,
            "total_attacks": report.total_attacks,
            "successful_attacks": report.successful_attacks,
            "overall_risk": report.overall_risk.value,
            "summary": report.summary,
        },
    }


def run_ai_scan(job_id, system_prompt, target_name, categories, budget, max_per_category):
    """Thread body: stream the agent, update the job, then map + score + persist."""
    try:
        cats = parse_categories(categories)
        jobs.set_progress(job_id, budget=budget, categories=len(cats))
        agent = build_agent()
        init = {
            "target_name": target_name, "system_prompt": system_prompt,
            "budget": budget, "max_per_category": max_per_category,
            "categories": cats, "log": [],
        }

        report = None
        # stream_mode="updates": each step yields {node_name: {returned keys}}.
        for step in agent.stream(init, config={"recursion_limit": 100}):
            for _node, upd in step.items():
                if isinstance(upd, dict):
                    if "log" in upd:                      # nodes return the FULL cumulative log
                        jobs.set_log(job_id, upd["log"])
                    if "total_attempts" in upd:
                        jobs.set_progress(job_id, attempts=upd["total_attempts"])
                    if upd.get("report") is not None:
                        report = upd["report"]

        if report is None:
            jobs.fail(job_id, "Agent finished without producing a report.")
            return

        rep = _map_report(report, target_name)
        all_findings = rep["findings"]
        sc = scoring.score_findings(all_findings)

        record = {
            "_id": new_id(), "_created": time.time(),
            "module": "ai", "target": target_name,
            "reports": [rep], "correlation": None, "graph": None,
            "exec_summary": "", "score": sc["score"],
            "meta": {
                "created": time.time(), "module": "ai", "target": target_name,
                "score": sc["score"], "band": sc["band"], "app_version": APP_VERSION,
                "engine": "RedCell (LangGraph autonomous red-team)",
                "total_attacks": report.total_attacks,
                "successful_attacks": report.successful_attacks,
                "overall_risk": report.overall_risk.value,
            },
        }
        get_store().save(record)

        jobs.finish(job_id, {
            "run_id": record["_id"], "report": rep,
            "score": sc["score"], "band": sc["band"],
            "total_attacks": report.total_attacks,
            "successful_attacks": report.successful_attacks,
            "overall_risk": report.overall_risk.value,
            "summary": report.summary,
        })
    except Exception as e:
        jobs.fail(job_id, f"{type(e).__name__}: {e}")
