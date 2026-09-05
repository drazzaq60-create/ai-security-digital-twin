# graph_model.py
# The shared attack graph: build it, score paths, find attack paths.
# Criticality is stored as a NODE attribute so ANY graph (hand-made OR built from a
# real scan) works with the same scoring + attack-path functions.

import networkx as nx


def build_graph() -> nx.DiGraph:
    """The original hand-made demo environment (used by the dashboard + simulation)."""
    G = nx.DiGraph()
    # each node carries a 'criticality' (0 = attacker start, 10 = crown jewel)
    for node, crit in {
        "Internet": 0, "WebServer": 3, "AppServer": 4,
        "ServiceAccount": 4, "AdminPanel": 6, "Database": 10,
    }.items():
        G.add_node(node, criticality=crit)

    # edges: weight = how dangerous the weakness is; vuln = what enables the step
    G.add_edge("Internet", "WebServer", weight=6, vuln="Outdated CMS (CVE-2023-1111)")
    G.add_edge("WebServer", "AppServer", weight=7, vuln="SQL Injection in login form")
    G.add_edge("AppServer", "ServiceAccount", weight=5, vuln="Hardcoded service credentials")
    G.add_edge("ServiceAccount", "Database", weight=9, vuln="Excessive DB permissions")
    G.add_edge("WebServer", "AdminPanel", weight=3, vuln="Weak admin password policy")
    G.add_edge("AdminPanel", "Database", weight=8, vuln="Admin panel has direct DB access")
    return G


def score_path(G: nx.DiGraph, path: list) -> int:
    """Risk = (sum of edge weights along the path) x (criticality of the final target)."""
    link_risk = sum(G[path[i]][path[i + 1]]["weight"] for i in range(len(path) - 1))
    target_criticality = G.nodes[path[-1]].get("criticality", 1)
    return link_risk * target_criticality


def find_attack_paths(G: nx.DiGraph, source: str, target: str):
    """Find every route from source to target, scored and sorted most-dangerous-first."""
    paths = list(nx.all_simple_paths(G, source=source, target=target))
    return sorted(((score_path(G, p), p) for p in paths), reverse=True)
