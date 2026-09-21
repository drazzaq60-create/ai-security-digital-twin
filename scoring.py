# scoring.py
# A deterministic 0-100 security score computed from findings (plus an optional signal
# from the attack-path graph). Shared by every scan type - AI red-team, web scan, and
# uploaded reports - so one number means the same thing across the whole platform.
#
# It is a HEURISTIC prioritisation signal, not a probability of breach. Lower = more/worse
# exposure. The formula is intentionally simple and explainable (each severity has a fixed
# point cost; Internet-reachable critical assets add a little more), so it can be defended.

# Point cost per finding, by severity. Higher = pulls the score down harder.
SEV_COST = {
    "critical": 50, "high": 25, "medium": 10, "low": 3,
    "info": 0, "none": 0, "unknown": 6,
}


def _sev(finding):
    return str(finding.get("severity", "unknown")).strip().lower()


def band(score):
    """Human label for a score."""
    if score >= 80:
        return "Low risk"
    if score >= 60:
        return "Moderate risk"
    if score >= 40:
        return "Elevated risk"
    if score >= 20:
        return "High risk"
    return "Critical risk"


def score_findings(findings, graph=None):
    """Return {score, band, penalty, severity_counts, reachable_critical}.

    score = 100 - penalty, where penalty is the summed severity cost (capped at 100)
    plus a small bump for Internet-reachable critical assets in the graph."""
    counts = {}
    for f in findings or []:
        s = _sev(f)
        counts[s] = counts.get(s, 0) + 1

    raw = sum(SEV_COST.get(s, 6) * n for s, n in counts.items())
    reach = len((graph or {}).get("reachable_critical") or [])
    raw += min(20, reach * 8)  # a reachable crown-jewel is worse than an isolated finding

    penalty = min(100, raw)
    score = max(0, 100 - penalty)
    return {
        "score": score,
        "band": band(score),
        "penalty": penalty,
        "severity_counts": counts,
        "reachable_critical": reach,
    }
