# tool_scan.py
# Runs REAL security scanners (Nmap, Nuclei, Nikto, sslscan) as live scans and parses their
# output into Sentinel's finding shape. These are powerful tools, so this is gated hard:
#
#   * OFF unless ENABLE_LIVE_TOOLS=1  (so a public deploy never becomes an open scan proxy).
#   * only tools actually installed on the host are offered (auto-detected).
#   * the target is SSRF-guarded (no private/internal hosts) unless SENTINEL_ALLOW_PRIVATE_TARGETS=1.
#   * each run has a hard timeout.
#
# Intended for LOCAL / self-hosted use (and screen-recorded demos). On the hosted demo the
# flag stays off and the lightweight stdlib scan is used instead.

import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET

from target_client import guard_url, TargetError
from deterministic_ingest import parse_deterministic

ENABLED = os.getenv("ENABLE_LIVE_TOOLS") == "1"
TIMEOUT = int(os.getenv("TOOL_TIMEOUT", "180"))  # seconds per tool run


def _sev_from_nuclei(s):
    return {"critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info"}.get(str(s).lower(), "Info")


def _f(name, host, severity, ftype, evidence, source):
    return {"name": name, "host": host, "severity": severity, "type": ftype,
            "evidence": str(evidence)[:400], "source": source}


# ---------------- per-tool command + parser ----------------
def _nmap_cmd(target):
    return ["nmap", "-T4", "-F", "-sV", "-oX", "-", target]


def _nmap_parse(stdout, host):
    # Reuse the already-tested Nmap XML parser.
    findings, _ = parse_deterministic(stdout, "scan.xml")
    return findings or []


def _nuclei_cmd(target):
    url = target if target.startswith(("http://", "https://")) else "https://" + target
    return ["nuclei", "-u", url, "-jsonl", "-silent"]


def _nuclei_parse(stdout, host):
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        info = d.get("info", {}) or {}
        out.append(_f(
            info.get("name") or d.get("template-id", "nuclei finding"),
            d.get("host") or host,
            _sev_from_nuclei(info.get("severity", "info")),
            "nuclei:" + (d.get("type", "")),
            f"{d.get('template-id','')} @ {d.get('matched-at', d.get('matched',''))}",
            "tool:nuclei",
        ))
    return out


def _sslscan_cmd(target):
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    return ["sslscan", "--xml=-", host]


def _sslscan_parse(stdout, host):
    out = []
    try:
        root = ET.fromstring(stdout)
    except Exception:
        return out
    for proto in root.iter("protocol"):
        name = (proto.get("type", "") + proto.get("version", "")).strip()
        if proto.get("enabled") == "1" and proto.get("version") in ("1.0", "1.1", "2", "3"):
            out.append(_f(f"Weak/legacy protocol enabled: {proto.get('type','').upper()} {proto.get('version')}",
                          host, "Medium", "tls", "sslscan: legacy protocol accepted", "tool:sslscan"))
    for cipher in root.iter("cipher"):
        if cipher.get("strength", "").lower() in ("weak", "null", "anonymous"):
            out.append(_f(f"Weak cipher: {cipher.get('cipher','')}", host, "Medium", "tls",
                          f"sslscan: {cipher.get('cipher','')} ({cipher.get('strength')})", "tool:sslscan"))
    return out


def _nikto_cmd(target):
    host = target if target.startswith(("http://", "https://")) else "https://" + target
    return ["nikto", "-h", host, "-Format", "json", "-o", "-", "-nointeractive"]


def _nikto_parse(stdout, host):
    out = []
    try:
        s, e = stdout.find("{"), stdout.rfind("}")
        data = json.loads(stdout[s:e + 1]) if s != -1 else {}
    except Exception:
        return out
    for v in (data.get("vulnerabilities") or []):
        out.append(_f(v.get("msg", "nikto finding")[:120], data.get("host", host), "Low", "web",
                      f"nikto {v.get('id','')}: {v.get('url','')}", "tool:nikto"))
    return out


TOOLS = {
    "nmap":    {"name": "Nmap",    "binary": "nmap",
                "desc": "Port + service discovery (what's exposed and what's running).",
                "cmd": _nmap_cmd, "parse": _nmap_parse},
    "nuclei":  {"name": "Nuclei",  "binary": "nuclei",
                "desc": "Template-based vulnerability scanner (thousands of known-issue checks).",
                "cmd": _nuclei_cmd, "parse": _nuclei_parse},
    "sslscan": {"name": "sslscan", "binary": "sslscan",
                "desc": "Deep TLS/SSL configuration audit (protocols, ciphers, certificate).",
                "cmd": _sslscan_cmd, "parse": _sslscan_parse},
    "nikto":   {"name": "Nikto",   "binary": "nikto",
                "desc": "Web-server scanner for known misconfigurations and dangerous files.",
                "cmd": _nikto_cmd, "parse": _nikto_parse},
}


def list_tools():
    """Return the tool catalog with install/availability status (for the UI)."""
    tools = [{"id": tid, "name": t["name"], "desc": t["desc"],
              "installed": bool(shutil.which(t["binary"]))} for tid, t in TOOLS.items()]
    return {"enabled": ENABLED, "tools": tools}


def run_tool(tool_id, target):
    """Run one tool against one target. Returns (findings, meta). Raises TargetError/ValueError
    for a disabled/missing tool or a blocked target."""
    if not ENABLED:
        raise ValueError("Live tools are disabled on this server (set ENABLE_LIVE_TOOLS=1 to use them).")
    tool = TOOLS.get(tool_id)
    if not tool:
        raise ValueError(f"Unknown tool: {tool_id}")
    if not shutil.which(tool["binary"]):
        raise ValueError(f"{tool['name']} is not installed on this server.")
    guard_url("http://" + target.replace("https://", "").replace("http://", ""))  # SSRF guard on the host

    proc = subprocess.run(tool["cmd"](target), capture_output=True, text=True, timeout=TIMEOUT)
    stdout = proc.stdout or proc.stderr
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = tool["parse"](stdout, host)
    return findings, {"tool": tool_id, "tool_name": tool["name"], "returncode": proc.returncode}


def run_tool_job(job_id, tool_id, target):
    """Thread body: run one real tool, map to findings, score, and persist as a web scan."""
    import time
    import jobs
    import scoring
    from store import get_store, new_id
    try:
        tname = TOOLS.get(tool_id, {}).get("name", tool_id)
        jobs.set_log(job_id, [f"Running {tname} against {target} … (up to {TIMEOUT}s)"])
        try:
            findings, meta = run_tool(tool_id, target)
        except subprocess.TimeoutExpired:
            jobs.fail(job_id, f"{tool_id} timed out after {TIMEOUT}s.")
            return
        except (TargetError, ValueError) as e:
            jobs.fail(job_id, str(e))
            return

        if not findings:
            findings = [_f("No issues reported by " + tool_id, target, "Info", "recon",
                           f"{tool_id} ran and returned no parseable findings.", "tool:" + tool_id)]
        rep = {
            "name": f"{meta['tool_name']}: {target}", "findings": findings, "fixes": [],
            "false_positives": [], "security": None, "parser": "tool:" + tool_id,
            "scan": {"target": target, "tool": tool_id, "tool_name": meta["tool_name"]},
        }
        sc = scoring.score_findings(findings)
        record = {
            "_id": new_id(), "_created": time.time(), "module": "web", "target": target,
            "reports": [rep], "correlation": None, "graph": None, "exec_summary": "",
            "score": sc["score"],
            "meta": {"created": time.time(), "module": "web", "target": target,
                     "score": sc["score"], "band": sc["band"], "engine": meta["tool_name"],
                     "tool": tool_id},
        }
        get_store().save(record)
        jobs.set_log(job_id, [f"Running {meta['tool_name']} against {target} …",
                              f"✓ {meta['tool_name']} complete — {len(findings)} finding(s), score {sc['score']}"])
        jobs.finish(job_id, {"run_id": record["_id"], "report": rep,
                             "score": sc["score"], "band": sc["band"], "findings": len(findings)})
    except Exception as e:
        jobs.fail(job_id, f"{type(e).__name__}: {e}")
