# ingest_zap.py
# M4: ingest an OWASP ZAP report (web-app scanner JSON) into our clean format.
# Adds web-application flaws (SQLi, XSS, ...) to the relevant host.

import json

# ZAP reports risk as words; we map them to numeric danger weights.
RISK_WEIGHT = {"High": 8, "Medium": 5, "Low": 2, "Informational": 1}


def parse_zap_report(path="sample_data/zap_report.json"):
    """Return {host: [ {name, weight}, ... ]}."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    host = data.get("host", "unknown")
    findings = {}
    for alert in data.get("alerts", []):
        findings.setdefault(host, []).append({
            "name": alert["name"],
            "weight": RISK_WEIGHT.get(alert.get("risk", "Low"), 2),
        })
    return findings


if __name__ == "__main__":
    for host, alerts in parse_zap_report().items():
        print(f"{host}:")
        for a in alerts:
            print(f"   - {a['name']}  (weight {a['weight']})")
