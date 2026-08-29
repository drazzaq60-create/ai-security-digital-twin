# dashboard.py
# M1 dashboard: shows the environment graph and every discovered attack path.

import streamlit as st
import matplotlib.pyplot as plt
import networkx as nx

from graph_model import build_graph, find_attack_paths

st.set_page_config(page_title="Security Digital Twin - M1", layout="wide")
st.title("🛡️ Security Digital Twin — Attack-Path Engine")

G = build_graph()
SOURCE, TARGET = "Internet", "Database"
scored_paths = find_attack_paths(G, SOURCE, TARGET)

col1, col2 = st.columns(2)

with col1:
    st.subheader("Environment Graph")
    fig, ax = plt.subplots(figsize=(6, 5))
    pos = nx.spring_layout(G, seed=42)
    colors = ["#ef4444" if n == TARGET else "#3b82f6" if n == SOURCE else "#94a3b8" for n in G.nodes()]
    nx.draw(G, pos, with_labels=True, node_color=colors, node_size=1800, font_size=8, ax=ax, arrows=True)
    edge_labels = {(u, v): d["weight"] for u, v, d in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, ax=ax, font_size=7)
    st.pyplot(fig)

with col2:
    st.subheader(f"Discovered Attack Paths ({SOURCE} → {TARGET})")
    for risk, path in scored_paths:
        with st.expander(f"Risk Score: {risk}  —  {' → '.join(path)}", expanded=(risk == scored_paths[0][0])):
            for i in range(len(path) - 1):
                vuln = G[path[i]][path[i + 1]]["vuln"]
                st.markdown(f"**{path[i]} → {path[i+1]}**  \nvia: _{vuln}_")