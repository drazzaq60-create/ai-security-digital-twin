# graph_model.py
# The shared "digital twin" graph — built once, reused everywhere (console + dashboard).

import networkx as nx

CRITICALITY = {
    "Internet": 0,
    "WebServer": 3,
    "AppServer": 4,
    "ServiceAccount": 4,
    "AdminPanel": 6,
    "Database": 10,
}

def build_graph() -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_edge("Internet", "WebServer", weight=6, vuln="Outdated CMS (CVE-2023-1111)")
    G.add_edge("WebServer", "AppServer", weight=7, vuln="SQL Injection in login form")
    G.add_edge("AppServer", "ServiceAccount", weight=5, vuln="Hardcoded service credentials")
    G.add_edge("ServiceAccount", "Database", weight=9, vuln="Excessive DB permissions")
    G.add_edge("WebServer", "AdminPanel", weight=3, vuln="Weak admin password policy")
    G.add_edge("AdminPanel", "Database", weight=8, vuln="Admin panel has direct DB access")
    return G

def score_path(G: nx.DiGraph, path: list) -> int:
    link_risk = sum(G[path[i]][path[i + 1]]["weight"] for i in range(len(path) - 1))
    return link_risk * CRITICALITY[path[-1]]

def find_attack_paths(G: nx.DiGraph, source: str, target: str):
    paths = list(nx.all_simple_paths(G, source=source, target=target))
    return sorted(((score_path(G, p), p) for p in paths), reverse=True)