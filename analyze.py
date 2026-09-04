# analyze.py
# THE WIRING: M1 (attack-path engine) + M2 (RAG brain) working together.
# It takes a discovered attack path and has the AI explain it and recommend the best fix,
# grounded in the security knowledge base (with citations).

from graph_model import build_graph, find_attack_paths
from rag_engine import retrieve
from llm import call_llm


def explain_attack_path(G, path):
    # 1. Describe the path step-by-step, pulling the vulnerability on each hop (from M1's graph)
    steps, vuln_terms = [], []
    for i in range(len(path) - 1):
        vuln = G[path[i]][path[i + 1]]["vuln"]
        steps.append(f"{path[i]} -> {path[i + 1]}  (via: {vuln})")
        vuln_terms.append(vuln)
    path_desc = "\n".join(steps)

    # 2. Retrieve knowledge about those vulnerabilities (from M2's knowledge base)
    context, sources = retrieve(" ".join(vuln_terms), n_results=4)

    # 3. Have the LLM explain the chain and recommend the single most effective fix
    system = (
        "You are a security analyst. You are given a discovered attack path and relevant "
        "security knowledge. Explain in plain language how an attacker would walk this path, "
        "then recommend the SINGLE most effective fix to break the chain and say why. "
        "Use ONLY the provided knowledge and cite sources in [brackets]."
    )
    user = (
        f"Discovered attack path:\n{path_desc}\n\n"
        f"Security knowledge:\n{context}\n\n"
        "Explain the path, then give the single best fix."
    )
    return call_llm(system, user), sources


if __name__ == "__main__":
    G = build_graph()
    scored = find_attack_paths(G, "Internet", "Database")
    top_risk, top_path = scored[0]  # the most dangerous path M1 found

    print(f"Most dangerous path (risk score {top_risk}):")
    print("  " + " -> ".join(top_path) + "\n")
    print("--- AI analysis (M1 path + M2 knowledge) ---\n")

    explanation, sources = explain_attack_path(G, top_path)
    print(explanation)
    print("\n(Knowledge from:", sources, ")")
