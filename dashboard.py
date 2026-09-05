# dashboard.py
# The visual for M1 + M3: environment graph, discovered attack paths,
# and an interactive what-if remediation simulator.

import streamlit as st
import matplotlib.pyplot as plt
import networkx as nx

from graph_model import build_graph, find_attack_paths
from simulate import compare_fixes, total_risk

st.set_page_config(page_title="Sentinel Security", layout="wide")
st.title("🛡️ Sentinel Security — Attack-Path & Remediation Engine")

G = build_graph()
SOURCE, TARGET = "Internet", "Database"
scored_paths = find_attack_paths(G, SOURCE, TARGET)
base_risk = total_risk(scored_paths)

# ---- headline metrics ----
c1, c2 = st.columns(2)
c1.metric("Attack paths found", len(scored_paths))
c2.metric("Total reachable risk", base_risk)

col1, col2 = st.columns(2)

with col1:
    st.subheader("Environment Graph")
    fig, ax = plt.subplots(figsize=(6, 5))
    pos = nx.spring_layout(G, seed=42)
    colors = ["#ef4444" if n == TARGET else "#3b82f6" if n == SOURCE else "#94a3b8" for n in G.nodes()]
    nx.draw(G, pos, with_labels=True, node_color=colors, node_size=1800, font_size=8, ax=ax, arrows=True)
    nx.draw_networkx_edge_labels(
        G, pos, edge_labels={(u, v): d["weight"] for u, v, d in G.edges(data=True)}, ax=ax, font_size=7
    )
    st.pyplot(fig)

with col2:
    st.subheader(f"Discovered Attack Paths ({SOURCE} → {TARGET})")
    for risk, path in scored_paths:
        with st.expander(f"Risk {risk}  —  {' → '.join(path)}", expanded=(risk == scored_paths[0][0])):
            for i in range(len(path) - 1):
                st.markdown(f"**{path[i]} → {path[i+1]}**  \nvia: _{G[path[i]][path[i+1]]['vuln']}_")

# ---- M3: what-if remediation simulation ----
st.divider()
st.subheader("🧪 What-If Remediation Simulation")

base_risk_c, base_paths_c, results = compare_fixes(G)

st.markdown("**Every fix, ranked by how much attack risk it removes:**")
st.dataframe(
    [
        {
            "Fix": r["fix"],
            "Location": r["edge"],
            "Paths": f"{r['paths_before']} → {r['paths_after']}",
            "Risk": f"{r['risk_before']} → {r['risk_after']}",
            "Risk removed": r["risk_removed"],
        }
        for r in results
    ],
    use_container_width=True,
    hide_index=True,
)

best = results[0]
st.success(
    f"**Best fix: {best['fix']}** — removes {best['risk_removed']} risk and eliminates "
    f"{best['paths_before'] - best['paths_after']} of {best['paths_before']} attack paths."
)

st.info(
    "Note: 'Excessive DB permissions' is the highest-severity single vuln (9), yet fixing the "
    "lower-severity CMS (6) removes far more risk — because of its position in the attack graph. "
    "That's why attack-path ranking beats severity-only prioritization."
)

st.markdown("**Try a fix and see the impact:**")
choice = st.selectbox("Pick a vulnerability to 'fix':", [r["fix"] for r in results])
chosen = next(r for r in results if r["fix"] == choice)

m1, m2, m3 = st.columns(3)
m1.metric("Attack paths remaining", chosen["paths_after"],
          delta=chosen["paths_after"] - chosen["paths_before"], delta_color="inverse")
m2.metric("Risk remaining", chosen["risk_after"],
          delta=-chosen["risk_removed"], delta_color="inverse")
pct = round(100 * chosen["risk_removed"] / base_risk_c) if base_risk_c else 0
m3.metric("Attack surface removed", f"{pct}%")
