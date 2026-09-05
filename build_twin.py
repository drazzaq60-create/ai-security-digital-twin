# build_twin.py
# The UNIFIED builder: combines multiple security tools into one attack graph.
#   Nmap                 -> hosts + services (the nodes)
#   Vuln scanner + ZAP   -> REAL vulnerabilities per host (the edge weights)
#   Wazuh                -> live alerts (context attached to each host)
#   Topology             -> which host reaches which
#
# The analysis engine (attack paths + simulation) is UNCHANGED - it doesn't care
# how many tools fed the graph. That is the whole point of a pluggable ingestion layer.

import networkx as nx

from ingest_nmap import parse_nmap
from ingest_vulns import parse_vuln_report
from ingest_zap import parse_zap_report
from ingest_wazuh import parse_wazuh_alerts
from graph_model import find_attack_paths
from simulate import compare_fixes

# Topology (from network documentation): what's internet-facing + who reaches whom.
INTERNET_FACING = {"web01"}
REACHES = {"web01": ["app01"], "app01": ["db01"]}
CRITICALITY = {"web01": 3, "app01": 4, "db01": 10}


def collect_vulns():
    """Merge REAL vulnerabilities from the vuln scanner AND OWASP ZAP -> {host: [(name, weight)]}."""
    vulns = {}
    for host, items in parse_vuln_report().items():
        for v in items:
            vulns.setdefault(host, []).append((v["name"], round(v["severity"])))
    for host, items in parse_zap_report().items():
        for v in items:
            vulns.setdefault(host, []).append((v["name"], v["weight"]))
    return vulns


def worst_vuln(vulns, host):
    """The most dangerous known vulnerability on a host (highest weight)."""
    items = vulns.get(host, [])
    return max(items, key=lambda t: t[1]) if items else None


def build_twin():
    hosts = parse_nmap("sample_data/scan.xml")
    by_name = {h["name"]: h for h in hosts}
    vulns = collect_vulns()
    alerts = parse_wazuh_alerts()

    G = nx.DiGraph()
    G.add_node("Internet", criticality=0)
    for name in by_name:
        G.add_node(name, criticality=CRITICALITY.get(name, 1), alerts=len(alerts.get(name, [])))

    def add_edge_to(src, dst):
        wv = worst_vuln(vulns, dst)  # move onto a host by exploiting its worst real vuln
        if wv:
            G.add_edge(src, dst, weight=wv[1], vuln=wv[0])

    for name in INTERNET_FACING:
        if name in by_name:
            add_edge_to("Internet", name)
    for src, dsts in REACHES.items():
        for dst in dsts:
            if dst in by_name:
                add_edge_to(src, dst)

    return G, alerts


if __name__ == "__main__":
    G, alerts = build_twin()
    print("Attack graph built from 4 tools: Nmap + Vuln scanner + OWASP ZAP + Wazuh.\n")

    print("Live alerts (from Wazuh):")
    for host, items in alerts.items():
        for a in items:
            print(f"   [{host}] level {a['level']}: {a['rule']}")
    print()

    scored = find_attack_paths(G, "Internet", "db01")
    print(f"Found {len(scored)} attack path(s) to db01:\n")
    for risk, path in scored:
        print(f"RISK {risk}: {' -> '.join(path)}")
        for i in range(len(path) - 1):
            print(f"    [{path[i]} -> {path[i + 1]}] via: {G[path[i]][path[i + 1]]['vuln']}")
        print()

    _, _, results = compare_fixes(G, "Internet", "db01")
    best = results[0]
    print(f">> BEST FIX: {best['fix']}")
    print(f"   removes {best['risk_removed']} risk, paths {best['paths_before']} -> {best['paths_after']}")
