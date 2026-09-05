# deterministic_ingest.py
# Ground-truth parsers for KNOWN report formats (Nmap XML, Nessus/OpenVAS-style vuln JSON,
# OWASP ZAP JSON, Wazuh alerts, SSL scans). For these we do NOT call the LLM: parsing is
# instant, deterministic, and — importantly for a security tool — cannot be manipulated by
# prompt-injection text inside the report, because we read structured fields, not free text.
# Unknown/odd formats fall back to the universal LLM parser.
#
# Every parser returns the same normalized finding shape the rest of the app expects:
#   {name, host, severity, type, evidence, source}

import json
import xml.etree.ElementTree as ET

_VALID_SEV = {"Critical", "High", "Medium", "Low", "Info", "Unknown"}
ZAP_RISK = {"high": "High", "medium": "Medium", "low": "Low", "informational": "Info", "info": "Info"}


def _f(name, host, severity, ftype, evidence, source):
    sev = severity if severity in _VALID_SEV else "Unknown"
    return {"name": str(name or "").strip() or "finding", "host": str(host or "unknown").strip(),
            "severity": sev, "type": ftype, "evidence": str(evidence or "").strip(), "source": source}


def _sev_from_cvss(v):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return "Unknown"
    if v >= 9:
        return "Critical"
    if v >= 7:
        return "High"
    if v >= 4:
        return "Medium"
    return "Low" if v > 0 else "Info"


def _sev_from_level(level):
    try:
        level = int(level)
    except (TypeError, ValueError):
        return "Unknown"
    if level >= 12:
        return "Critical"
    if level >= 10:
        return "High"
    if level >= 7:
        return "Medium"
    return "Low"


def _parse_nmap(text, source):
    root = ET.fromstring(text)
    out = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr = host.find("address[@addrtype='ipv4']")
        ip = addr.get("addr") if addr is not None else "unknown"
        nm = host.find("hostnames/hostname")
        hn = nm.get("name") if nm is not None else ip
        for port in host.findall("ports/port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = port.find("service")
            sname = (svc.get("name") if svc is not None else "unknown") or "unknown"
            banner = " ".join(x for x in [(svc.get("product") if svc is not None else ""),
                                          (svc.get("version") if svc is not None else "")] if x).strip()
            label = f"Open {sname} ({port.get('portid')}/{port.get('protocol')})"
            if banner:
                label += f" — {banner}"
            # An open port is EXPOSURE, not a confirmed vuln -> type=service, severity Info.
            out.append(_f(label, hn, "Info", "service", f"nmap: {sname} {banner}".strip(), source))
    return out


def _parse_vulns(data, source):
    out = []
    for host, vulns in data.items():
        for v in vulns:
            cve = v.get("cve", "")
            out.append(_f(f"{cve} {v.get('name', '')}".strip(), host,
                          _sev_from_cvss(v.get("severity")), "vulnerability",
                          f"CVSS {v.get('severity')}", source))
    return out


def _parse_ssl(data, source):
    out = []
    for host, items in data.items():
        for it in items:
            out.append(_f(it.get("issue", ""), host, (it.get("severity") or "Unknown").title(),
                          "config", "SSL/TLS scan", source))
    return out


def _parse_zap_simple(data, source):
    host = data.get("host") or data.get("site") or "unknown"
    out = []
    for a in data.get("alerts", []):
        cwe = a.get("cweid")
        out.append(_f(a.get("name", ""), host, ZAP_RISK.get((a.get("risk") or "").lower(), "Unknown"),
                      "web", "OWASP ZAP" + (f" · CWE-{cwe}" if cwe else ""), source))
    return out


def _parse_zap_real(data, source):
    out = []
    for site in data.get("site", []):
        host = site.get("@name") or site.get("name") or "unknown"
        for a in site.get("alerts", []):
            name = a.get("alert") or a.get("name") or ""
            risk = (a.get("riskdesc") or a.get("risk") or "").split(" ")[0]
            cwe = a.get("cweid")
            out.append(_f(name, host, ZAP_RISK.get(risk.lower(), "Unknown"), "web",
                          "OWASP ZAP" + (f" · CWE-{cwe}" if cwe else ""), source))
    return out


def _parse_wazuh(data, source):
    return [_f(a.get("rule", ""), a.get("host", "unknown"), _sev_from_level(a.get("level")),
               "alert", f"Wazuh level {a.get('level')}", source) for a in data]


def parse_deterministic(text, filename="report"):
    """Return (findings, format_label) for a known format, else (None, None)."""
    src = filename
    # --- Nmap XML ---
    if "<nmaprun" in text[:4000]:
        try:
            return _parse_nmap(text, src), "nmap"
        except Exception:
            return None, None

    # --- JSON formats ---
    try:
        data = json.loads(text)
    except Exception:
        return None, None
    try:
        if isinstance(data, list):
            if data and isinstance(data[0], dict) and "rule" in data[0] and "level" in data[0]:
                return _parse_wazuh(data, src), "wazuh"
            return None, None
        if isinstance(data, dict):
            if isinstance(data.get("site"), list):
                return _parse_zap_real(data, src), "owasp_zap"
            if "alerts" in data and ("host" in data or "site" in data):
                return _parse_zap_simple(data, src), "owasp_zap"
            # dict of host -> list-of-findings (only if EVERY value is a list, to avoid misfires)
            vals = [v for v in data.values() if isinstance(v, list)]
            if data and len(vals) == len(data):
                first = (vals[0][0] if vals[0] else {}) if vals else {}
                if isinstance(first, dict):
                    if "cve" in first:
                        return _parse_vulns(data, src), "vuln_scan"
                    if "issue" in first:
                        return _parse_ssl(data, src), "ssl_scan"
    except Exception:
        return None, None
    return None, None


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_data/scan.xml"
    with open(path, "r", encoding="utf-8") as fh:
        findings, fmt = parse_deterministic(fh.read(), path)
    print(f"format: {fmt} | findings: {len(findings or [])}")
    for x in (findings or []):
        print(f"  {x['severity']:9} {x['type']:13} {x['host']:12} {x['name']}")
