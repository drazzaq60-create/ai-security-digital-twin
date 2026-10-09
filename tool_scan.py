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
import tempfile
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


def _whatweb_cmd(target):
    url = target if target.startswith(("http://", "https://")) else "https://" + target
    return ["whatweb", "--log-json={OUT}", "--no-errors", "-q", url]


def _whatweb_parse(output, host):
    try:
        data = json.loads(output)
    except Exception:
        data = [json.loads(l) for l in output.splitlines() if l.strip().startswith("{")] or []
    techs = set()
    for entry in (data if isinstance(data, list) else [data]):
        for name, info in (entry.get("plugins") or {}).items():
            ver = ""
            if isinstance(info, dict) and info.get("version"):
                ver = " " + ",".join(str(v) for v in info["version"])
            techs.add((name + ver).strip())
    if not techs:
        return []
    return [_f("Technology stack fingerprinted", host, "Info", "recon",
               "whatweb detected: " + ", ".join(sorted(techs)[:25]), "tool:whatweb")]


# Wapiti: active web-app DAST (SQLi, XSS, path traversal, command exec, SSRF, …).
_WAPITI_SEV = {
    "SQL Injection": "High", "Blind SQL Injection": "High", "Cross Site Scripting": "High",
    "Command execution": "Critical", "Path Traversal": "High", "Server Side Request Forgery": "High",
    "XML External Entity": "High", "CRLF Injection": "Medium", "Open Redirect": "Medium",
    "Backup file": "Medium", "Htaccess Bypass": "Medium", "Secure Flag cookie": "Low",
    "HttpOnly Flag cookie": "Low", "Content Security Policy Configuration": "Low",
    "HTTP Secure Headers": "Low", "Internal Server Error": "Low", "Fingerprint web technology": "Info",
}


def _wapiti_cmd(target):
    url = target if target.startswith(("http://", "https://")) else "https://" + target
    return ["wapiti", "-u", url, "--format", "json", "-o", "{OUT}",
            "--flush-session", "--scope", "folder", "--max-scan-time", str(TIMEOUT)]


def _wapiti_parse(output, host):
    out = []
    try:
        data = json.loads(output)
    except Exception:
        return out
    for category, items in (data.get("vulnerabilities") or {}).items():
        sev = _WAPITI_SEV.get(category, "Medium")
        for it in (items or []):
            detail = f"{it.get('method','')} {it.get('path','')} — {it.get('info','')}".strip()
            out.append(_f(category, host, sev, "webapp", detail, "tool:wapiti"))
    return out


def _testssl_cmd(target):
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    return ["testssl.sh", "--jsonfile", "{OUT}", "--quiet", "--color", "0", host]


def _testssl_parse(output, host):
    out = []
    smap = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "WARN": "Low"}
    try:
        data = json.loads(output)
    except Exception:
        return out
    for e in (data if isinstance(data, list) else data.get("scanResult", [])):
        sev = smap.get(str(e.get("severity", "")).upper())
        if not sev:
            continue
        out.append(_f(e.get("id", "tls finding"), host, sev, "tls",
                      e.get("finding", ""), "tool:testssl"))
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
    "wapiti":  {"name": "Wapiti",  "binary": "wapiti", "outfile": True,
                "desc": "Active web-app scanner (SQL injection, XSS, path traversal, command exec, SSRF).",
                "cmd": _wapiti_cmd, "parse": _wapiti_parse},
    "whatweb": {"name": "WhatWeb", "binary": "whatweb", "outfile": True,
                "desc": "Fingerprints the tech stack (server, framework, CMS, versions) — recon.",
                "cmd": _whatweb_cmd, "parse": _whatweb_parse},
    "testssl": {"name": "testssl.sh", "binary": "testssl.sh", "outfile": True,
                "desc": "Comprehensive TLS/SSL audit (protocols, ciphers, vulns like Heartbleed/ROBOT).",
                "cmd": _testssl_cmd, "parse": _testssl_parse},
}


def list_tools():
    """Return the tool catalog with install/availability status (for the UI)."""
    tools = [{"id": tid, "name": t["name"], "desc": t["desc"],
              "installed": bool(shutil.which(t["binary"]))} for tid, t in TOOLS.items()]
    return {"enabled": ENABLED, "tools": tools}


def _host_of(target):
    return target.replace("https://", "").replace("http://", "").split("/")[0]


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
    guard_url("http://" + _host_of(target))  # SSRF guard on the host

    cmd = tool["cmd"](target)
    outfile = None
    if tool.get("outfile"):  # tool writes its report to a file ({OUT} placeholder)
        fd, outfile = tempfile.mkstemp(suffix=".out")
        os.close(fd)
        cmd = [a.replace("{OUT}", outfile) for a in cmd]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        if outfile:
            try:
                with open(outfile, encoding="utf-8", errors="ignore") as f:
                    output = f.read()
            except Exception:
                output = proc.stdout or proc.stderr
        else:
            output = proc.stdout or proc.stderr
    finally:
        if outfile:
            try: os.remove(outfile)
            except OSError: pass

    findings = tool["parse"](output, _host_of(target))
    return findings, {"tool": tool_id, "tool_name": tool["name"], "returncode": proc.returncode}


def run_tools(target, tool_ids, log=None):
    """Run the chosen installed tools against one target and merge (dedup) the findings.
    `tool_ids` may include 'all' (= every installed tool). `log(msg)` is an optional callback."""
    if not tool_ids or "all" in tool_ids:
        tool_ids = list(TOOLS.keys())
    merged, ran = [], []
    for tid in tool_ids:
        t = TOOLS.get(tid)
        if not t or not shutil.which(t["binary"]):
            continue
        if log:
            log(f"Running {t['name']} …")
        try:
            f, _ = run_tool(tid, target)
            merged += f
            ran.append(t["name"])
        except Exception as e:
            if log:
                log(f"  {t['name']} skipped: {e}")
    seen, out = set(), []
    for f in merged:
        k = (f["name"], f["host"], f["source"])
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out, ran


def run_tool_job(job_id, tools, target):
    """Thread body: run the chosen tool(s), merge to findings, score, persist as a web scan.
    `tools` is a list of tool ids (may be ['all'])."""
    import time
    import jobs
    import scoring
    from store import get_store, new_id
    try:
        _logbuf = []
        def _log(msg):
            _logbuf.append(msg); jobs.set_log(job_id, list(_logbuf))

        if not ENABLED:
            jobs.fail(job_id, "Live tools are disabled on this server (set ENABLE_LIVE_TOOLS=1).")
            return
        try:
            guard_url("http://" + _host_of(target))
        except TargetError as e:
            jobs.fail(job_id, str(e)); return

        _log(f"Scanning {target} with {len(tools) if 'all' not in tools and tools else 'all'} tool(s)…")
        findings, ran = run_tools(target, tools, log=_log)
        tool_name = ran[0] if len(ran) == 1 else f"Multi-tool scan ({', '.join(ran)})" if ran else "Tool scan"
        parser_tag = ran[0].lower() if len(ran) == 1 else "multi"

        if not findings:
            findings = [_f("No issues reported", target, "Info", "recon",
                           "The tool(s) ran and returned no parseable findings.", "tool:scan")]
        rep = {
            "name": f"{tool_name}: {target}", "findings": findings, "fixes": [],
            "false_positives": [], "security": None, "parser": "tool:" + parser_tag,
            "scan": {"target": target, "tools": ran, "tool_name": tool_name},
        }
        sc = scoring.score_findings(findings)
        record = {
            "_id": new_id(), "_created": time.time(), "module": "web", "target": target,
            "reports": [rep], "correlation": None, "graph": None, "exec_summary": "",
            "score": sc["score"],
            "meta": {"created": time.time(), "module": "web", "target": target,
                     "score": sc["score"], "band": sc["band"], "engine": tool_name,
                     "tools": ran},
        }
        get_store().save(record)
        _log(f"✓ complete — {len(findings)} finding(s), score {sc['score']} ({sc['band']})")
        jobs.finish(job_id, {"run_id": record["_id"], "report": rep,
                             "score": sc["score"], "band": sc["band"], "findings": len(findings)})
    except Exception as e:
        jobs.fail(job_id, f"{type(e).__name__}: {e}")
