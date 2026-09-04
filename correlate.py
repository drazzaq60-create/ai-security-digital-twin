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
        "You are a senior security analyst correlating findings from MULTIPLE reports/tools.\n"
        "STEP 1 - Decide relatedness: compare host/asset/domain/scope and decide whether the reports "
        "concern the SAME target/environment or DIFFERENT, unrelated targets.\n"
        "STRICT RULES (follow exactly):\n"
        "- CONFIRMED: include an issue ONLY if two or more tools report the SAME issue on the SAME "
        "asset/host. Never across different assets or unrelated reports.\n"
        "- HIDDEN_RISKS: combine findings ONLY on the same or clearly connected assets in one "
        "environment. Never invent a chain across unrelated targets.\n"
        "- COMMON_FIXES: shared remediations addressing multiple correlated findings - ONLY when related.\n"
        "- If the reports cover DIFFERENT, unrelated targets, set related=false and return EMPTY confirmed, "
        "hidden_risks and common_fixes. Do NOT fabricate correlations. Empty is the correct answer.\n"
        "- If unsure whether two findings relate, do NOT correlate them.\n"
        'Return ONLY a JSON object: {"scope": "one sentence: same target or different/unrelated?", '
        '"related": true or false, "confirmed": [], "hidden_risks": [], "common_fixes": []}. '
        'confirmed/hidden_risks items: {"summary": "...", "hosts": [...], "tools": [...], "why": "..."}; '
        "common_fixes is an array of short strings. Base everything ONLY on the findings provided."
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
    print(f"scope: {result.get('scope', '')}")
    print(f"related: {result.get('related')}\n")
    for section, label in [("confirmed", "CONFIRMED (multiple tools agree)"),
                           ("hidden_risks", "HIDDEN / CHAINED RISKS")]:
        print(f"=== {label} ===")
        for item in result.get(section, []):
            print(f" - {item.get('summary', '')}")
            print(f"     hosts: {item.get('hosts')}   tools: {item.get('tools')}")
            print(f"     why: {item.get('why', '')}\n")
        print()
    print("=== COMMON FIXES ===")
    for fix in result.get("common_fixes", []):
        print(f" - {fix}")
