# ingest_vulns.py
# M4: ingest a vulnerability-scanner report (Nessus/OpenVAS-style JSON) into our clean format.
# Gives us REAL per-host CVEs instead of guessing from version numbers.

import json


def parse_vuln_report(path="sample_data/vulns.json"):
    """Return {host: [ {cve, name, severity}, ... ]}."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


if __name__ == "__main__":
    data = parse_vuln_report()
    for host, vulns in data.items():
        print(f"{host}:")
        for v in vulns:
            print(f"   - {v['cve']}  {v['name']}  (CVSS {v['severity']})")
