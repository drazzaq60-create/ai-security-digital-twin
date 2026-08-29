# attack_path_engine.py
# M1: The Attack-Path Engine
# Models a tiny security environment as a graph and finds attack paths to a critical asset.

import networkx as nx

# STEP 1: Build the security graph.
# Node = something in the environment. Edge = "can reach", with a danger "weight" (1-10)
# and which real-world weakness ("vuln") makes that step possible.

G = nx.DiGraph()  # DiGraph = a directed graph: attacks flow one way, deeper into the network

G.add_edge("Internet", "WebServer", weight=6, vuln="Outdated CMS (CVE-2023-1111)")
G.add_edge("WebServer", "AppServer", weight=7, vuln="SQL Injection in login form")
G.add_edge("AppServer", "ServiceAccount", weight=5, vuln="Hardcoded service credentials")
G.add_edge("ServiceAccount", "Database", weight=9, vuln="Excessive DB permissions")
G.add_edge("WebServer", "AdminPanel", weight=3, vuln="Weak admin password policy")
G.add_edge("AdminPanel", "Database", weight=8, vuln="Admin panel has direct DB access")

# STEP 2: How much each asset matters if an attacker reaches it.
CRITICALITY = {
    "Internet": 0,
    "WebServer": 3,
    "AppServer": 4,
    "ServiceAccount": 4,
    "AdminPanel": 6,
    "Database": 10,  # the crown jewel
}

SOURCE = "Internet"
TARGET = "Database"

# STEP 3: Find every possible route from Internet to Database.
paths = list(nx.all_simple_paths(G, source=SOURCE, target=TARGET))

# STEP 4: Score each route: total danger along the way x how critical the target is.
def score_path(path):
    link_risk = sum(G[path[i]][path[i + 1]]["weight"] for i in range(len(path) - 1))
    target_criticality = CRITICALITY[path[-1]]
    return link_risk * target_criticality

# STEP 5: Report, most dangerous path first.
print(f"Found {len(paths)} attack path(s) from {SOURCE} to {TARGET}:\n")

scored_paths = sorted(
    ((score_path(p), p) for p in paths),
    reverse=True,
)

for risk, path in scored_paths:
    print(f"RISK SCORE: {risk}")
    print("  " + " -> ".join(path))
    for i in range(len(path) - 1):
        vuln = G[path[i]][path[i + 1]]["vuln"]
        print(f"    [{path[i]} -> {path[i + 1]}]  via: {vuln}")
    print()