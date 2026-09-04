# ingest_wazuh.py
# M4: ingest Wazuh alerts (SIEM/log events, JSON) into our clean format.
# These are LIVE alerts (what's happening now) - context, not graph edges.

import json


def parse_wazuh_alerts(path="sample_data/wazuh_alerts.json"):
    """Return {host: [ {rule, level, timestamp}, ... ]}."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    alerts = {}
    for a in data:
        alerts.setdefault(a["host"], []).append(a)
    return alerts


if __name__ == "__main__":
    for host, items in parse_wazuh_alerts().items():
        print(f"{host}:")
        for a in items:
            print(f"   - [level {a['level']}] {a['rule']}")
