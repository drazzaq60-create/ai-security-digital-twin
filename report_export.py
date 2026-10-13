# report_export.py
# Renders a full Sentinel analysis into a shareable PDF (so a report can leave the app -
# for a client, a ticket, or a portfolio). Uses fpdf2 (pure-python, no system deps).
# fpdf2 core fonts are latin-1, and findings text is English, so we sanitise to latin-1.

from datetime import datetime
from fpdf import FPDF

INK = (30, 41, 59)
MUTED = (110, 120, 135)
MINT = (5, 150, 105)
RED = (220, 60, 60)
AMBER = (200, 130, 10)


def _s(text):
    """Make any string safe for the latin-1 core fonts."""
    return str(text or "").encode("latin-1", "replace").decode("latin-1")


class _PDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*MUTED)
        self.cell(0, 8, "Sentinel Security", align="L")
        self.cell(0, 8, datetime.now().strftime("%Y-%m-%d %H:%M"), align="R", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 8, f"Page {self.page_no()}/{{nb}}", align="C")


def _h1(pdf, text):
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(*INK)
    pdf.multi_cell(0, 8, _s(text), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def _h2(pdf, text, color=INK):
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 7, _s(text), new_x="LMARGIN", new_y="NEXT")


def _p(pdf, text, size=10, color=INK):
    pdf.set_font("Helvetica", "", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 5.5, _s(text), new_x="LMARGIN", new_y="NEXT")


def _bullet(pdf, text, color=INK):
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 5.5, _s("  - " + text), new_x="LMARGIN", new_y="NEXT")


def _render_markdown(pdf, md):
    """Render the LLM report markdown into the PDF (headings, tables, bullets, bold-stripped).
    Deliberately simple — fpdf2 core fonts, latin-1."""
    lines = str(md or "").replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        # Table: header row of `| ... |` then a `|---|` separator.
        if line.strip().startswith("|") and i + 1 < len(lines) and "-" in lines[i + 1] and set(lines[i + 1].strip()) <= set("|-: "):
            cells = lambda row: [c.strip() for c in row.strip().strip("|").split("|")]
            header = cells(line)
            i += 2
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(cells(lines[i])); i += 1
            pdf.set_font("Helvetica", "B", 8); pdf.set_text_color(*MUTED)
            _p(pdf, " | ".join(header), size=8, color=MUTED)
            pdf.set_text_color(*INK)
            for r in rows:
                _bullet(pdf, " | ".join(r), color=INK)
            continue
        h = line.lstrip("#").strip() if line.lstrip().startswith("#") else None
        if h is not None:
            level = len(line) - len(line.lstrip("#"))
            _h1(pdf, _strip_md(h)) if level <= 1 else _h2(pdf, _strip_md(h))
            i += 1
            continue
        if line.lstrip().startswith(("-", "*")):
            _bullet(pdf, _strip_md(line.lstrip()[1:].strip()))
            i += 1
            continue
        import re as _re
        if _re.match(r"^\s*\d+[.)]\s+", line):
            _bullet(pdf, _strip_md(_re.sub(r"^\s*\d+[.)]\s+", "", line)))
            i += 1
            continue
        _p(pdf, _strip_md(line))
        i += 1
    pdf.ln(2)


def _strip_md(text):
    """Drop inline markdown markers (**bold**, `code`) for the plaintext PDF."""
    import re as _re
    return _re.sub(r"\*\*([^*]+)\*\*", r"\1", str(text)).replace("`", "")


def build_pdf(data):
    """data = {reports:[...], correlation:{...}|None, graph:{...}|None}. Returns PDF bytes."""
    reports = data.get("reports", []) or []
    correlation = data.get("correlation") or {}
    graph = data.get("graph") or {}

    pdf = _PDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()

    _h1(pdf, "Security Analysis Report")

    total_findings = sum(len(r.get("findings", []) or []) for r in reports)
    injections = sum(1 for r in reports if (r.get("security") or {}).get("injection_detected"))
    _p(pdf, f"Reports analyzed: {len(reports)}    Findings: {total_findings}    "
            f"Prompt-injection events: {injections}", color=MUTED)

    # --- Executive summary (if generated) ---
    summary_text = (data.get("exec_summary") or "").strip()
    if summary_text:
        _h2(pdf, "Executive Summary")
        for line in summary_text.splitlines():
            if line.strip():
                _p(pdf, line)

    # --- LLM-written comprehensive report (real-tool web scan) ---
    report_md = next((r.get("report_md") for r in reports if r.get("report_md")), "")
    if report_md:
        _render_markdown(pdf, report_md)

    # --- Guardrails (honest: only claim what actually ran) ---
    def _evaluated(r):
        s = r.get("security") or {}
        return isinstance(s.get("injection_detected"), bool)

    def _na(r):  # web/port scan or external scanner: no untrusted text reaches the LLM
        return (not _evaluated(r)) and str(r.get("parser") or "").startswith(("live", "tool:"))

    flagged = [r for r in reports if _evaluated(r) and ((r.get("security") or {}).get("injection_detected")
                                                        or (r.get("security") or {}).get("output_ok") is False)]
    passed = [r for r in reports if _evaluated(r) and r not in flagged]
    na = [r for r in reports if _na(r)]
    not_eval = [r for r in reports if not _evaluated(r) and not _na(r)]

    _h2(pdf, "Guardrails (LLM security)", color=RED if flagged else (MINT if passed else MUTED))
    if flagged:
        for r in flagged:
            sec = r.get("security") or {}
            _p(pdf, f"{r.get('name','?')}: {sec.get('count',0)} attempt(s), "
                    f"max severity {sec.get('max_severity','?')} - detected and blocked.")
            for d in sec.get("detections", [])[:5]:
                _bullet(pdf, f"{d.get('technique','?')} ({d.get('severity','?')})", color=MUTED)
    if passed:
        _p(pdf, f"{len(passed)} uploaded report(s) passed - scanned for injection (L1), hardened "
                "so report text is treated as data not instructions (L2), responses checked (L3).", color=MINT)
    if na:
        _p(pdf, f"{len(na)} report(s) not applicable - web/port or external-scanner results don't feed "
                "untrusted text into the LLM, so the prompt-injection guardrails don't apply here.", color=MUTED)
    if not_eval:
        _p(pdf, f"{len(not_eval)} uploaded report(s) not evaluated - no scan metadata "
                "(unreadable/empty file, or a run saved before guardrails existed). This is NOT a pass.", color=MUTED)
    if not (flagged or passed or na or not_eval):
        _p(pdf, "No reports were security-evaluated in this run.", color=MUTED)

    # --- Attack paths ---
    if graph.get("paths"):
        _h2(pdf, "Attack paths to critical assets")
        _p(pdf, "Heuristic priority = asset criticality x path exploit-likelihood (inferred "
                "topology; not a breach probability).", size=9, color=MUTED)
        for pth in graph.get("paths", [])[:8]:
            chain = " -> ".join(pth.get("path", []))
            _bullet(pdf, f"{chain}   [priority {pth.get('priority')}, "
                         f"likelihood {pth.get('likelihood')}%, target crit {pth.get('criticality')}/5]")

    # --- Cross-tool correlation ---
    if correlation.get("related"):
        _h2(pdf, "Cross-tool correlation")
        for item in correlation.get("confirmed", [])[:6]:
            _bullet(pdf, "CONFIRMED: " + item.get("summary", ""))
        for item in correlation.get("hidden_risks", [])[:6]:
            _bullet(pdf, "HIDDEN: " + item.get("summary", ""))

    # --- Per-report detail ---
    _h2(pdf, "Findings by report")
    for r in reports:
        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 6, _s(f"{r.get('name','?')}  ({len(r.get('findings', []) or [])} findings)"),
                       new_x="LMARGIN", new_y="NEXT")
        for f in r.get("findings", []) or []:
            sev = (f.get("severity") or "Unknown")
            col = RED if sev.lower() in ("critical", "high") else AMBER if sev.lower() == "medium" else MUTED
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*col)
            pdf.cell(24, 5.5, _s(sev))
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*INK)
            pdf.multi_cell(0, 5.5, _s(f"{f.get('name','')}  @ {f.get('host','')}"),
                           new_x="LMARGIN", new_y="NEXT")
        fixes = r.get("fixes", []) or []
        if fixes:
            _p(pdf, "Prioritized fixes:", size=9, color=MUTED)
            for fx in fixes:
                _bullet(pdf, fx)

    return bytes(pdf.output())
