# correlate.py
# Cross-tool correlation - the intelligence a single scanner cannot provide.
# It combines findings from MULTIPLE tools and uses the LLM to identify:
#   - CONFIRMED    : issues corroborated by 2+ tools (higher confidence)
#   - FALSE POSITIVES : findings likely false / low-signal (with reasoning)
#   - HIDDEN RISKS : dangers that emerge ONLY by combining tools (chains no single tool sees)

import json
from llm import call_llm
from ingest_nmap import parse_nmap
from ingest_vulns import parse_vuln_report
from ingest_zap import parse_zap_report
from ingest_wazuh import parse_wazuh_alerts


def gather_all_findings():
    """Pull findings from every tool into one combined list (source-labelled)."""
    findings = []
    for h in parse_nmap():
        for s in h["services"]:
            desc = f"open {s['name']} {s['product']} {s['version']}".strip()
            findings.append({"source": "nmap", "host": h["name"], "finding": desc})
    for host, vulns in parse_vuln_report().items():
        for v in vulns:
            findings.append({"source": "vuln_scan", "host": host,
                             "finding": f"{v['cve']} {v['name']} (CVSS {v['severity']})"})
    for host, alerts in parse_zap_report().items():
        for a in alerts:
            findings.append({"source": "owasp_zap", "host": host,
                             "finding": f"{a['name']} (risk weight {a['weight']})"})
    for host, alerts in parse_wazuh_alerts().items():
        for a in alerts:
            findings.append({"source": "wazuh", "host": host,
                             "finding": f"{a['rule']} (level {a['level']})"})
    return findings


def correlate(findings):
    """Ask the LLM to correlate findings across tools into confirmed / false-positive / hidden."""
    system = (
        "You are a senior security analyst correlating findings from MULTIPLE tools. "
        "Analyze the combined findings and return ONLY a JSON object with exactly these three arrays:\n"
        '  "confirmed": issues corroborated by 2+ tools (higher confidence),\n'
        '  "false_positives": findings likely false or low-signal (say why),\n'
        '  "hidden_risks": dangers that emerge ONLY by combining tools - for example, a web SQL-injection '
        "finding on one host PLUS SIEM alerts of active SQL-injection attempts elsewhere can indicate an "
        "active exploitation chain no single tool would flag.\n"
        'Each array item must be: {"summary": "...", "hosts": [...], "tools": [...], "why": "..."}. '
        "Base everything ONLY on the findings provided; do not invent anything."
    )
    user = "COMBINED FINDINGS (JSON):\n" + json.dumps(findings, indent=2)
    raw = call_llm(system, user)
    try:
        start, end = raw.find("{"), raw.rfind("}")
        return json.loads(raw[start:end + 1]) if start != -1 and end != -1 else {"raw": raw}
    except Exception:
        return {"raw": raw}


if __name__ == "__main__":
    findings = gather_all_findings()
    print(f"Gathered {len(findings)} findings across all tools. Correlating...\n")
    result = correlate(findings)
    for section, label in [("confirmed", "CONFIRMED (multiple tools agree)"),
                           ("false_positives", "LIKELY FALSE POSITIVES"),
                           ("hidden_risks", "HIDDEN / CHAINED RISKS")]:
        print(f"=== {label} ===")
        for item in result.get(section, []):
            print(f" - {item.get('summary', '')}")
            print(f"     hosts: {item.get('hosts')}   tools: {item.get('tools')}")
            print(f"     why: {item.get('why', '')}\n")
        print()
