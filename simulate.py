# simulate.py
# M3: What-If Simulation.
# "If we fix vulnerability X, how many attack paths disappear and how much risk drops?"
# It copies the graph, removes one edge (= the fix), recomputes paths, and compares.

import copy
from graph_model import build_graph, find_attack_paths

SOURCE, TARGET = "Internet", "Database"


def total_risk(scored_paths):
    """Add up the risk scores of every attack path (0 if there are none left)."""
    return sum(risk for risk, _ in scored_paths)


def simulate_fix(G, u, v):
    """Return a COPY of the graph with one edge (one vulnerability) removed = 'fixed'."""
    G2 = copy.deepcopy(G)
    if G2.has_edge(u, v):
        G2.remove_edge(u, v)
    return G2


def compare_fixes(G, source=SOURCE, target=TARGET):
    """Try fixing each vulnerability one at a time; rank fixes by how much risk they remove."""
    baseline = find_attack_paths(G, source, target)
    base_risk = total_risk(baseline)

    results = []
    for u, v, data in G.edges(data=True):
        after = find_attack_paths(simulate_fix(G, u, v), source, target)
        results.append({
            "fix": data["vuln"],
            "edge": f"{u} -> {v}",
            "paths_before": len(baseline),
            "paths_after": len(after),
            "risk_before": base_risk,
            "risk_after": total_risk(after),
            "risk_removed": base_risk - total_risk(after),
        })

    results.sort(key=lambda r: r["risk_removed"], reverse=True)  # biggest impact first
    return base_risk, len(baseline), results


if __name__ == "__main__":
    G = build_graph()
    base_risk, base_paths, results = compare_fixes(G)

    print(f"BEFORE any fix: {base_paths} attack paths, total risk = {base_risk}\n")
    print("Ranking every possible fix by how much attack risk it removes:\n")
    for r in results:
        print(f"  Fix: {r['fix']}  ({r['edge']})")
        print(f"     paths {r['paths_before']} -> {r['paths_after']}   |   "
              f"risk {r['risk_before']} -> {r['risk_after']}   |   removed: {r['risk_removed']}\n")

    best = results[0]
    print(f">> BEST FIX: {best['fix']}")
    print(f"   removes {best['risk_removed']} risk and eliminates "
          f"{best['paths_before'] - best['paths_after']} of {best['paths_before']} attack path(s).")
