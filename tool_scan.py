# tool_scan.py
# Runs REAL security scanners (Nmap, Nuclei, Nikto, sslscan) as live scans and parses their
# output into Sentinel's finding shape. These are powerful tools, so this is gated hard:
#
#   * ON by default for local dev, OFF on a public host (so a public deploy never becomes an
#     open scan proxy); ENABLE_LIVE_TOOLS=0/1 overrides. See runtime_env.py.
#   * only tools actually installed on the host are offered (auto-detected).
#   * the target is SSRF-guarded (no private/internal hosts) on public hosts; localhost is
#     allowed locally by default (SENTINEL_ALLOW_PRIVATE_TARGETS=0/1 overrides).
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
from runtime_env import env_flag, is_public_deploy

# Default ON for local dev, OFF on a public host (so a public deploy never becomes an
# open scan proxy). An explicit ENABLE_LIVE_TOOLS=0/1 always overrides.
ENABLED = env_flag("ENABLE_LIVE_TOOLS", default=not is_public_deploy())
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
    # Bound it: skip the huge 'info' template set (tech-detect etc.), focus on real-severity
    # findings, tighten timeouts/concurrency so a scan finishes well within the tool timeout.
    return ["nuclei", "-u", url, "-jsonl", "-silent",
            "-severity", "low,medium,high,critical",
            "-timeout", "6", "-retries", "1", "-c", "40", "-rl", "200"]


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


def _nuclei_ready():
    """Nuclei's binary is useless without templates; treat it as available only when some exist."""
    base = os.path.join(os.path.expanduser("~"), "nuclei-templates")
    if not os.path.isdir(base):
        return False
    for _root, _dirs, files in os.walk(base):
        if any(f.endswith(".yaml") for f in files):
            return True
    return False


# Tools that behave well on Windows. Nuclei is pathologically slow loading its ~14k-template
# tree on Windows (scans blow past the timeout and return nothing) and Wapiti is flaky here;
# the TLS/web tools (sslscan, nikto, whatweb, testssl) are POSIX-only. So on Windows we offer
# ONLY Nmap and show everything else as "coming soon". The full suite lights up automatically
# on a Linux self-host / deploy, where these binaries actually work.
WINDOWS_OK = {"nmap"}


def _available(tool_id, binary):
    """A tool is usable only if its binary is present AND any runtime prerequisites are met
    (e.g. Nuclei needs its templates). Prevents offering a tool that would just fail."""
    if os.name == "nt" and tool_id not in WINDOWS_OK:
        return False  # Windows: only Nmap is reliable; the rest show as "coming soon"
    if not shutil.which(binary):
        return False
    if tool_id == "nuclei":
        return _nuclei_ready()
    return True


def list_tools():
    """Return the tool catalog with install/availability status (for the UI)."""
    tools = [{"id": tid, "name": t["name"], "desc": t["desc"],
              "installed": _available(tid, t["binary"])} for tid, t in TOOLS.items()]
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
    if not _available(tool_id, tool["binary"]):
        if tool_id == "nuclei" and shutil.which(tool["binary"]):
            raise ValueError("Nuclei has no templates yet (run `nuclei -update-templates`).")
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
    return findings, {"tool": tool_id, "tool_name": tool["name"],
                      "returncode": proc.returncode,
                      "stderr": (proc.stderr or "").strip()[:600],
                      "empty_output": not (output or "").strip(),
                      "raw": (output or "").strip()}  # full tool output (appendix + LLM context)


def run_tool_job(job_id, tools, target):
    """Thread body: run each chosen tool against the target, keep each tool's FULL raw
    output, then have the LLM synthesise ONE comprehensive pentest-style report from all
    the findings + raw output. Returns a single merged report (findings + report markdown
    + per-tool raw appendix). `tools` is a list of tool ids (may be ['all'])."""
    import jobs
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

        tool_ids = list(TOOLS.keys()) if (not tools or "all" in tools) else tools
        host = _host_of(target)
        merged_findings = []          # all findings across tools (each keeps its source tool)
        raw_by_tool = []              # [{tool, tool_name, raw, returncode, ok, note}]
        ran, failed_tools = [], []
        _log(f"Scanning {target} …")
        for tid in tool_ids:
            t = TOOLS.get(tid)
            if not t or not _available(tid, t["binary"]):   # skip not-ready tools (e.g. nuclei w/o templates)
                continue
            _log(f"Running {t['name']} …")
            try:
                findings, meta = run_tool(tid, target)
            except Exception as e:
                _log(f"  {t['name']} could not run: {e}")
                ran.append(t["name"]); failed_tools.append(t["name"])
                raw_by_tool.append({"tool": tid, "tool_name": t["name"], "raw": "",
                                    "returncode": None, "ok": False, "note": str(e)[:300]})
                continue
            ran.append(t["name"])
            rc = meta.get("returncode")
            # A tool with no findings AND an error/empty output has FAILED — never a clean pass
            # (classic: Nmap without Npcap on Windows exits in ~1s with no output).
            tool_failed = (not findings) and (meta.get("empty_output") or (rc not in (0, None)))
            if tool_failed:
                note = meta.get("stderr") or f"exited with code {rc}, no parseable output"
                failed_tools.append(t["name"])
                _log(f"  ⚠ {t['name']} failed (exit {rc}): {note.splitlines()[0][:160] if note else ''}")
            else:
                _log(f"  {t['name']}: {len(findings)} finding(s)" if findings else f"  {t['name']}: no findings (clean)")
                merged_findings += findings
            raw_by_tool.append({
                "tool": tid, "tool_name": t["name"], "raw": meta.get("raw", ""),
                "returncode": rc, "ok": not tool_failed,
                "note": (meta.get("stderr") or "")[:300] if tool_failed else "",
            })

        if not ran:
            jobs.fail(job_id, "None of the selected tools are installed/available on this server.")
            return

        # De-dup merged findings (same tools can report the same thing).
        seen, deduped = set(), []
        for f in merged_findings:
            k = (f.get("name"), f.get("host"), f.get("source"))
            if k in seen:
                continue
            seen.add(k); deduped.append(f)

        # LLM: synthesise one comprehensive report from everything gathered.
        _log("Synthesising comprehensive report (LLM)…")
        try:
            from tool_report import build_comprehensive_report
            report_md = build_comprehensive_report(target, ran, deduped, raw_by_tool, failed_tools)
            _log("  ✓ report written")
        except Exception as e:
            report_md = ""
            _log(f"  ⚠ LLM report unavailable: {e}")

        status = "ok" if deduped else ("failed" if failed_tools and not deduped else "empty")
        rep = {
            "name": f"Security scan — {host}",
            "findings": deduped, "fixes": [], "false_positives": [],
            "status": status,
            "error": ("; ".join(f"{n} failed" for n in failed_tools) if (failed_tools and not deduped) else ""),
            "security": None, "parser": "tool:multi",
            "report_md": report_md,
            "scan": {"target": target, "tools": ran, "failed_tools": failed_tools,
                     "raw": raw_by_tool},
        }
        _log(f"✓ scan complete — {len(deduped)} finding(s) across {len(ran)} tool(s): {', '.join(ran)}"
             + (f" ({len(failed_tools)} failed)" if failed_tools else ""))
        jobs.finish(job_id, {"reports": [rep], "tools": ran,
                             "findings": len(deduped), "failed_tools": failed_tools})
    except Exception as e:
        jobs.fail(job_id, f"{type(e).__name__}: {e}")
