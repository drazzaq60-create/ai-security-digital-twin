# web_graph.py
# Builds an attack-surface graph FROM THE UPLOADED FINDINGS (not a hardcoded topology),
# so the Digital Twin is tied to real evidence. It is deliberately honest about what it
# does and does not know:
#
#   * Topology (who can reach whom) is NOT in a vulnerability report. We INFER it with
#     clearly-stated assumptions (returned in `assumptions`) and label every inferred edge
#     `assumed=True`. Incomplete/unproven chains are hypotheses, not facts.
#   * The score is a HEURISTIC PRIORITY, not a breach probability. We model each hop as an
#     independent exploit-likelihood in (0,1] and multiply them along a path, so a LONGER
#     chain scores LOWER (harder), and shared weaknesses are not double-counted. Priority =
#     asset criticality x path likelihood.
#
# Everything here is deterministic (networkx only) - no LLM - so it is fast and repeatable.

import ipaddress
import networkx as nx

# Per-hop exploit likelihood by severity (independent-step model -> product along a path).
SEV_EXPLOIT = {"critical": 0.9, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1, "unknown": 0.1}
SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 1}

DB_HINTS = ("mysql", "postgres", "postgresql", "mssql", "sql server", "mariadb", "mongo",
            "redis", "oracle", "database", "3306", "5432", "1433", "27017")
WEB_HINTS = ("http", "https", "apache", "nginx", "tomcat", "iis", "web", "port 80",
             "port 443", "8080", "8443", "django", "express", "php", "wordpress")

CRIT_ASSET = 4  # criticality >= this counts as a "crown jewel" target
SCORING_VERSION = "1.0"  # bump when the graph/scoring logic changes (recorded in run provenance)


def _is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _subnet(h):
    return ".".join(h.split(".")[:3]) if _is_ip(h) else None


def _host_findings(findings):
    hosts = {}
    for f in findings:
        h = (f.get("host") or "").strip()
        if not h or h.lower() == "unknown":
            continue
        hosts.setdefault(h, []).append(f)
    return hosts


def _text(fs):
    return " ".join(
        ((f.get("name") or "") + " " + (f.get("type") or "") + " " + (f.get("evidence") or "")).lower()
        for f in fs
    )


def _worst(fs):
    """Return (severity_label, finding_name) for the highest-severity finding on a host."""
    best = None
    for f in fs:
        r = SEV_RANK.get((f.get("severity") or "unknown").lower(), 1)
        if best is None or r > best[0]:
            best = (r, f.get("severity") or "Unknown", f.get("name") or "finding")
    return ("Unknown", "exposure") if best is None else (best[1], best[2])


EXPLOIT_TYPES = {"vulnerability", "web", "alert"}


def _edge_basis(fs):
    """What KIND of transition does the evidence support on the destination host?

    Returns (basis, severity, via):
      - "exploit"  : a real vulnerability (Medium+ vuln/web/alert finding, or a CVE) that
                     could actually enable moving onto the host -> a genuine attack step.
      - "exposure" : only an open/observed service (Info/Low, or type=service) -> reachable
                     and exposed, but NOT a confirmed exploitable transition.
    This is the core of not calling an open port an 'attack step'."""
    best = None
    for f in fs:
        sev = (f.get("severity") or "unknown").lower()
        typ = (f.get("type") or "other").lower()
        text = ((f.get("name") or "") + " " + (f.get("evidence") or "")).lower()
        is_exploit = ("cve-" in text) or (typ in EXPLOIT_TYPES and SEV_RANK.get(sev, 1) >= 3)
        if is_exploit:
            r = SEV_RANK.get(sev, 1)
            if best is None or r > best[0]:
                best = (r, f.get("severity") or "Unknown", f.get("name") or "finding")
    if best:
        return ("exploit", best[1], best[2])
    sev, via = _worst(fs)
    return ("exposure", sev, via)


# Control-specific remediation verbs (feature #3): the action fits what the edge represents.
CONTROL_ACTION = {
    "internet": "Restrict Internet exposure of {v}",
    "lateral": "Restrict / segment network access to {v}",
    "firewall": "Block the network route {u} → {v}",
    "network": "Restrict the network route {u} → {v}",
    "service": "Restrict the exposed service on {v}",
    "port": "Close / restrict the exposed port on {v}",
    "trust": "Revoke the trust relationship {u} → {v}",
    "identity": "Revoke identity trust {u} → {v}",
    "permission": "Revoke excessive permission {u} → {v}",
}


def _action(basis, u, v, control, via):
    """Honest remediation verb: exploit steps get 'Remediate <vuln>'; other steps get the
    control-specific action for their edge type."""
    if basis == "exploit":
        return f"Remediate: {via} on {v}"
    return CONTROL_ACTION.get(control, "Restrict access {u} → {v}").format(u=u, v=v)


def _criticality(fs):
    t = _text(fs)
    if any(k in t for k in DB_HINTS):
        return 5  # datastore = crown jewel
    if any(k in t for k in WEB_HINTS):
        return 3  # web/app server
    return 2      # other host


def _internet_facing(fs):
    return any(k in _text(fs) for k in WEB_HINTS)


def _norm_name(n):
    n = str(n or "").strip()
    return "Internet" if n.lower() == "internet" else n


def build_web_graph(findings, topology=None):
    """Build nodes + edges + attack paths from findings, optionally using a USER-SUPPLIED
    topology (real connections between assets). With supplied topology, a path that uses only
    supplied edges AND has an exploitable finding at every hop is CONFIRMED; without it,
    connectivity is inferred and every path is hypothetical."""
    hf = _host_findings(findings)
    assumptions = []

    # Optional criticality overrides + supplied edges from a topology file.
    asset_over, supplied = {}, []
    if isinstance(topology, dict):
        for name, meta in (topology.get("assets") or {}).items():
            if isinstance(meta, dict) and "criticality" in meta:
                try:
                    asset_over[_norm_name(name)] = int(meta["criticality"])
                except (TypeError, ValueError):
                    pass
        for e in (topology.get("edges") or []):
            if not isinstance(e, dict):
                continue
            u, v = _norm_name(e.get("from")), _norm_name(e.get("to"))
            if u and v and u != v:
                supplied.append((u, v, str(e.get("control") or "network").strip().lower()))
    use_supplied = len(supplied) > 0

    # ---- nodes ----
    node_names = set(hf.keys())
    for u, v, _ in supplied:
        node_names.add(u); node_names.add(v)
    node_names.discard("Internet")

    def crit_of(name):
        if name in asset_over:
            return asset_over[name]
        return _criticality(hf[name]) if name in hf else 2

    nodes = [{"id": "Internet", "criticality": 0, "internet_facing": False, "kind": "internet", "findings": 0}]
    facing = []
    for name in node_names:
        fs = hf.get(name, [])
        crit = crit_of(name)
        face = _internet_facing(fs) if fs else False
        if face:
            facing.append(name)
        kind = "database" if crit >= 5 else ("web" if crit == 3 else "host")
        nodes.append({"id": name, "criticality": crit, "internet_facing": face,
                      "kind": kind, "findings": len(fs)})

    # ---- edges ----
    edges = []

    def make_edge(u, v, control, supplied_flag):
        fs = hf.get(v, [])
        basis, sev, via = _edge_basis(fs) if fs else ("exposure", "Unknown", "connection")
        like = SEV_EXPLOIT.get(sev.lower(), 0.1) if basis == "exploit" else 0.15
        edges.append({"source": u, "target": v, "basis": basis,
                      "topology": "supplied" if supplied_flag else "inferred",
                      "severity": sev, "exploit": like, "via": via,
                      "assumed": not supplied_flag, "control": control,
                      "action": _action(basis, u, v, control, via)})

    if use_supplied:
        for u, v, control in supplied:
            make_edge(u, v, control, True)
        assumptions.append("Topology is USER-SUPPLIED. A path that uses only supplied edges AND has an "
                           "exploitable finding at every hop is CONFIRMED; others remain hypothetical.")
    else:
        if not facing:
            facing = list(hf.keys())
            assumptions.append("No clearly internet-facing service was detected, so every scanned host "
                               "is treated as reachable from the Internet (assumption).")
        else:
            assumptions.append("Internet exposure was inferred from web/service findings; hosts without "
                               "such findings are treated as internal-only.")
        for h in facing:
            make_edge("Internet", h, "internet", False)
        hosts = list(hf.keys())
        lateral = False
        for a in hosts:
            for b in hosts:
                if a == b:
                    continue
                sa, sb = _subnet(a), _subnet(b)
                if sa and sb and sa == sb:
                    make_edge(a, b, "lateral", False)
                    lateral = True
        if lateral:
            assumptions.append("Lateral movement is assumed between hosts on the same /24 subnet; the "
                               "reports do not prove these paths exist.")
        assumptions.append("All paths are HYPOTHETICAL without a supplied topology: connectivity is "
                           "inferred. 'Vuln-backed' = exploitable finding at every hop; 'exposure-only' "
                           "= includes open-service steps. Upload a topology file for confirmed paths.")

    assumptions.append("Asset criticality is a heuristic (datastore=high, web/app=medium, other=low) "
                       "unless overridden in the topology file.")

    result = compute_paths(nodes, edges)
    result.update({"nodes": nodes, "edges": edges, "assumptions": assumptions,
                   "scoring_version": SCORING_VERSION, "topology_supplied": use_supplied})
    return result


def _graph_from(nodes, edges, skip=None):
    G = nx.DiGraph()
    for n in nodes:
        G.add_node(n["id"], **{k: v for k, v in n.items() if k != "id"})
    for e in edges:
        if skip and e["source"] == skip[0] and e["target"] == skip[1]:
            continue
        G.add_edge(e["source"], e["target"], exploit=e.get("exploit", 0.1),
                   severity=e.get("severity", "Unknown"), via=e.get("via", ""),
                   basis=e.get("basis", "exposure"), action=e.get("action", ""),
                   topology=e.get("topology", "inferred"), control=e.get("control", ""))
    return G


def compute_paths(nodes, edges, skip=None):
    """Enumerate Internet->critical-asset paths, scored by likelihood x criticality."""
    G = _graph_from(nodes, edges, skip=skip)
    crit_map = {n["id"]: n.get("criticality", 1) for n in nodes}
    targets = [n["id"] for n in nodes if n.get("criticality", 0) >= CRIT_ASSET]
    if not targets:  # nothing high-value detected -> fall back to web/app tier
        targets = [n["id"] for n in nodes if n.get("criticality", 0) >= 3]

    paths, reachable = [], set()
    if "Internet" in G:
        for t in targets:
            if t not in G or t == "Internet":
                continue
            for p in nx.all_simple_paths(G, "Internet", t, cutoff=6):
                like, steps = 1.0, []
                for i in range(len(p) - 1):
                    ed = G[p[i]][p[i + 1]]
                    like *= ed["exploit"]
                    steps.append({"from": p[i], "to": p[i + 1], "severity": ed["severity"],
                                  "via": ed["via"], "basis": ed.get("basis", "exposure"),
                                  "action": ed.get("action", ""), "control": ed.get("control", ""),
                                  "topology": ed.get("topology", "inferred")})
                crit = crit_map.get(t, 1)
                all_exploit = bool(steps) and all(s["basis"] == "exploit" for s in steps)
                all_supplied = bool(steps) and all(s.get("topology") == "supplied" for s in steps)
                # CONFIRMED needs real topology AND a real vuln at every hop; otherwise hypothetical.
                if all_supplied and all_exploit:
                    path_class = "confirmed"
                elif all_exploit:
                    path_class = "vuln"
                else:
                    path_class = "exposure"
                paths.append({"path": p, "steps": steps, "target": t, "criticality": crit,
                              "likelihood": round(like * 100), "priority": round(crit * like * 100),
                              "path_class": path_class, "confirmed": path_class == "confirmed"})
                reachable.add(t)

    paths.sort(key=lambda x: x["priority"], reverse=True)
    return {"paths": paths[:15], "reachable_critical": sorted(reachable),
            "critical_assets": sorted(targets)}


def simulate_cut(nodes, edges, cut):
    """What-if: remove one (assumed) edge and recompute reachability + paths."""
    before = compute_paths(nodes, edges)
    after = compute_paths(nodes, edges, skip=(cut[0], cut[1]))
    return {"before": before, "after": after, "cut": cut}
