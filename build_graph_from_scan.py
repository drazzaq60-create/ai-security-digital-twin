# build_graph_from_scan.py
# M4 Step 2: turn a REAL Nmap scan into an attack graph, then run the M1/M3 engine on it.

import networkx as nx
from ingest_nmap import parse_nmap
from graph_model import find_attack_paths
from simulate import compare_fixes

# --- ENRICHMENT: map detected software versions to known vulnerabilities + danger weight ---
# In a full system this comes from a CVE feed / vuln scanner; here it's a small rules table.
VULN_RULES = [
    ("Apache httpd", "2.4.49", "Apache Path Traversal/RCE (CVE-2021-41773)", 9),
    ("Apache Tomcat", "9.0.30", "Tomcat AJP 'Ghostcat' (CVE-2020-1938)", 7),
    ("MySQL", "5.7", "Exposed / outdated MySQL", 6),
    ("OpenSSH", "7.4", "Outdated OpenSSH", 4),
]

# --- TOPOLOGY (from network documentation): what's internet-facing + who reaches whom ---
INTERNET_FACING = {"web01"}
REACHES = {"web01": ["app01"], "app01": ["db01"]}      # tier-to-tier reachability
CRITICALITY = {"web01": 3, "app01": 4, "db01": 10}     # db01 is the crown jewel


def worst_vuln_for_host(host):
    """Return (vuln_name, weight) for the most dangerous known vuln on a host, or None."""
    best = None
    for svc in host["services"]:
        for product, ver_prefix, vuln, weight in VULN_RULES:
            if svc["product"] == product and svc["version"].startswith(ver_prefix):
                if best is None or weight > best[1]:
                    best = (vuln, weight)
    return best


def build_graph_from_scan(path="sample_data/scan.xml"):
    hosts = parse_nmap(path)
    by_name = {h["name"]: h for h in hosts}

    G = nx.DiGraph()
    G.add_node("Internet", criticality=0)
    for name in by_name:
        G.add_node(name, criticality=CRITICALITY.get(name, 1))

    # An edge means: you can move onto a host by exploiting ITS worst vulnerability.
    def add_edge_to(src, dst_name):
        vuln = worst_vuln_for_host(by_name[dst_name])
        if vuln:
            G.add_edge(src, dst_name, weight=vuln[1], vuln=vuln[0])

    for name in INTERNET_FACING:
        if name in by_name:
            add_edge_to("Internet", name)
    for src, dsts in REACHES.items():
        for dst in dsts:
            if dst in by_name:
                add_edge_to(src, dst)
    return G


if __name__ == "__main__":
    G = build_graph_from_scan()
    print("Attack graph built from the REAL Nmap scan.\n")

    scored = find_attack_paths(G, "Internet", "db01")
    print(f"Found {len(scored)} attack path(s) to db01:\n")
    for risk, path in scored:
        print(f"RISK {risk}: {' -> '.join(path)}")
        for i in range(len(path) - 1):
            print(f"    [{path[i]} -> {path[i + 1]}] via: {G[path[i]][path[i + 1]]['vuln']}")
        print()

    # The M3 simulation works on this real-data graph too (same code, reused):
    _, _, results = compare_fixes(G, "Internet", "db01")
    best = results[0]
    print(f">> BEST FIX (from real scan): {best['fix']}")
    print(f"   removes {best['risk_removed']} risk, paths {best['paths_before']} -> {best['paths_after']}")
