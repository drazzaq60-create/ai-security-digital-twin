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


def _action(basis, dst, via, internet):
    """Honest remediation verb for an edge, based on what it actually represents."""
    if basis == "exploit":
        return f"Remediate: {via} on {dst}"
    if internet:
        return f"Restrict Internet exposure of {dst}"
    return f"Restrict / segment network access to {dst}"


def _criticality(fs):
    t = _text(fs)
    if any(k in t for k in DB_HINTS):
        return 5  # datastore = crown jewel
    if any(k in t for k in WEB_HINTS):
        return 3  # web/app server
    return 2      # other host


def _internet_facing(fs):
    return any(k in _text(fs) for k in WEB_HINTS)


def build_web_graph(findings):
    """Build nodes + edges + attack paths + explicit assumptions from raw findings."""
    hf = _host_findings(findings)
    nodes = [{"id": "Internet", "criticality": 0, "internet_facing": False, "kind": "internet", "findings": 0}]
    assumptions = []
    facing = []

    for h, fs in hf.items():
        crit = _criticality(fs)
        face = _internet_facing(fs)
        if face:
            facing.append(h)
        kind = "database" if crit == 5 else ("web" if crit == 3 else "host")
        nodes.append({"id": h, "criticality": crit, "internet_facing": face,
                      "kind": kind, "findings": len(fs)})

    edges = []

    def add_edge(u, v, internet=False):
        basis, sev, via = _edge_basis(hf[v])
        # exposure-only steps get a low, fixed likelihood (reachable, not proven exploitable);
        # exploit steps scale with the vuln severity.
        like = SEV_EXPLOIT.get(sev.lower(), 0.1) if basis == "exploit" else 0.15
        edges.append({"source": u, "target": v, "basis": basis, "topology": "inferred",
                      "severity": sev, "exploit": like, "via": via, "assumed": True,
                      "action": _action(basis, v, via, internet)})

    if not facing:
        facing = list(hf.keys())
        assumptions.append("No clearly internet-facing service was detected, so every scanned host "
                           "is treated as reachable from the Internet (assumption).")
    else:
        assumptions.append("Internet exposure was inferred from web/service findings; hosts without "
                           "such findings are treated as internal-only.")

    for h in facing:
        add_edge("Internet", h, internet=True)

    hosts = list(hf.keys())
    lateral = False
    for a in hosts:
        for b in hosts:
            if a == b:
                continue
            sa, sb = _subnet(a), _subnet(b)
            if sa and sb and sa == sb:
                add_edge(a, b)
                lateral = True
    if lateral:
        assumptions.append("Lateral movement is assumed between hosts on the same /24 subnet; the "
                           "reports do not prove these paths exist.")
    assumptions.append("Asset criticality is a heuristic (datastore = high, web/app = medium, other "
                       "= low), not confirmed business value.")
    assumptions.append("All paths are HYPOTHETICAL: topology is inferred, so no path is a confirmed "
                       "attack path. 'Vuln-backed' paths have an exploitable finding at every hop; "
                       "'exposure-only' paths include steps that are merely open services.")

    result = compute_paths(nodes, edges)
    result.update({"nodes": nodes, "edges": edges, "assumptions": assumptions,
                   "scoring_version": SCORING_VERSION})
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
                   basis=e.get("basis", "exposure"), action=e.get("action", ""))
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
                                  "action": ed.get("action", "")})
                crit = crit_map.get(t, 1)
                # Every path here is HYPOTHETICAL (topology is inferred, never supplied).
                # vuln-backed = an exploitable vuln at every hop; exposure = >=1 open-service hop.
                path_class = "vuln" if steps and all(s["basis"] == "exploit" for s in steps) else "exposure"
                paths.append({"path": p, "steps": steps, "target": t, "criticality": crit,
                              "likelihood": round(like * 100), "priority": round(crit * like * 100),
                              "path_class": path_class, "confirmed": False})
                reachable.add(t)

    paths.sort(key=lambda x: x["priority"], reverse=True)
    return {"paths": paths[:15], "reachable_critical": sorted(reachable),
            "critical_assets": sorted(targets)}


def simulate_cut(nodes, edges, cut):
    """What-if: remove one (assumed) edge and recompute reachability + paths."""
    before = compute_paths(nodes, edges)
    after = compute_paths(nodes, edges, skip=(cut[0], cut[1]))
    return {"before": before, "after": after, "cut": cut}
