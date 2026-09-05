"use client";

import { useState, useRef, useMemo, useEffect } from "react";

// Configurable so a deployed build can point at a real backend, not the visitor's own PC.
const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function Home() {
  const [files, setFiles] = useState([]);
  const [message, setMessage] = useState("");
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState([]);
  const [reports, setReports] = useState([]);
  const [correlation, setCorrelation] = useState(null);
  const [correlationError, setCorrelationError] = useState("");
  const [graph, setGraph] = useState(null);
  const [graphError, setGraphError] = useState("");
  const [sim, setSim] = useState(null);
  const [simCut, setSimCut] = useState(null);
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const [runs, setRuns] = useState([]);
  const [runMeta, setRunMeta] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const [hideTagged, setHideTagged] = useState(false);
  const [topology, setTopology] = useState(null);
  const [topoName, setTopoName] = useState("");
  const inputRef = useRef(null);
  const topoRef = useRef(null);

  async function loadTopology(file) {
    if (!file) return;
    try {
      const text = await file.text();
      const obj = JSON.parse(text);
      if (!obj || !Array.isArray(obj.edges)) throw new Error("missing an \"edges\" array");
      setTopology(obj); setTopoName(file.name); setError("");
    } catch (e) {
      setTopology(null); setTopoName("");
      setError(`Topology file invalid: ${(e && e.message) || "not JSON"}. Expected {"edges":[{"from","to","control"}]}.`);
    }
  }
  function clearTopology() { setTopology(null); setTopoName(""); if (topoRef.current) topoRef.current.value = ""; }
  const abortRef = useRef(null);
  const timerRef = useRef(null);

  const STAGE_TIMEOUT = 180000;  // per-stage cap (ms) — a hung request can't block forever

  function errMsg(e) {
    if (e?.name === "TimeoutError") return "timed out";
    if (e?.name === "AbortError") return "cancelled";
    return (e && e.message) || "error";
  }

  // fetch with a per-stage timeout, also abortable by the master cancel signal.
  async function fetchStage(url, opts, extSignal) {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(new DOMException("timeout", "TimeoutError")), STAGE_TIMEOUT);
    const onAbort = () => ctrl.abort(new DOMException("cancelled", "AbortError"));
    if (extSignal) { if (extSignal.aborted) onAbort(); else extSignal.addEventListener("abort", onAbort); }
    try {
      return await fetch(url, { ...opts, signal: ctrl.signal });
    } finally {
      clearTimeout(to);
      if (extSignal) extSignal.removeEventListener("abort", onAbort);
    }
  }

  async function loadRuns() {
    try {
      const r = await fetch(`${API_URL}/runs`);
      if (r.ok) { const d = await r.json(); setRuns(d.runs || []); }
    } catch { /* history is best-effort */ }
  }
  useEffect(() => { loadRuns(); }, []);

  function addFiles(list) {
    const incoming = Array.from(list);
    setFiles((prev) => {
      const names = new Set(prev.map((f) => f.name));
      return [...prev, ...incoming.filter((f) => !names.has(f.name))];
    });
  }
  function removeFile(name) { setFiles((prev) => prev.filter((f) => f.name !== name)); }
  function logLine(text, kind = "info") {
    setLog((prev) => [...prev, { text, kind, t: new Date().toLocaleTimeString() }]);
  }

  // One report's full pipeline (extract -> fixes). Reused by analyze() and retryReport().
  async function analyzeOne(f, signal) {
    const rep = {
      name: f.name, findings: [], fixes: [], false_positives: [],
      status: "ok", error: "", fixesFailed: false, security: null, parser: null,
    };
    logLine(`Extracting findings from ${f.name}…`);
    try {
      const form = new FormData();
      form.append("file", f);
      const eRes = await fetchStage(`${API_URL}/extract`, { method: "POST", body: form }, signal);
      if (!eRes.ok) throw new Error(`extract failed (${eRes.status})`);
      const eData = await eRes.json();
      rep.name = eData.name || f.name;
      rep.sha256 = eData.sha256 || null;
      rep.parser = eData.parser || null;
      rep.security = eData.security || null;
      if (rep.parser && rep.parser.startsWith("deterministic:")) {
        logLine(`⚡ ${rep.name}: parsed by ${rep.parser.split(":")[1]} parser (deterministic, no LLM)`, "ok");
      }
      if (rep.security?.injection_detected) {
        logLine(`🛡️ ${rep.name}: prompt-injection detected — ${rep.security.count} attempt(s), ${rep.security.max_severity} severity (blocked, findings still extracted)`, "err");
      }
      if (eData.error) {
        rep.status = "failed"; rep.error = eData.error;
        logLine(`✗ ${rep.name}: ${eData.error}`, "err");
        return rep;
      }
      rep.findings = eData.findings || [];
      if (rep.findings.length === 0) {
        rep.status = "empty";
        logLine(`• ${rep.name}: no findings extracted`, "info");
      } else {
        logLine(`✓ ${rep.name}: ${rep.findings.length} findings`, "ok");
      }
    } catch (e) {
      rep.status = "failed"; rep.error = errMsg(e);
      logLine(`✗ ${rep.name}: ${rep.error}`, "err");
      return rep;
    }

    if (rep.findings.length > 0) {
      logLine(`Analyzing ${rep.name} (fixes + false positives)… waiting for model`);
      try {
        const rRes = await fetchStage(`${API_URL}/report-fixes`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: rep.name, findings: rep.findings, focus: message }),
        }, signal);
        if (!rRes.ok) throw new Error(`fixes failed (${rRes.status})`);
        const rData = await rRes.json();
        rep.fixes = rData.fixes || [];
        rep.false_positives = rData.false_positives || [];
      } catch (e) {
        rep.fixesFailed = true;
        logLine(`✗ ${rep.name}: fixes step failed (${errMsg(e)})`, "err");
      }
    }
    return rep;
  }

  async function analyze() {
    if (files.length === 0) { setError("Add at least one report file."); return; }
    setError(""); setRunning(true); setLog([]); setReports([]);
    setCorrelation(null); setCorrelationError("");
    setGraph(null); setGraphError(""); setSim(null); setSimCut(null); setRunMeta(null);
    const collected = [];
    let allFindings = [];

    const ac = new AbortController();
    abortRef.current = ac;
    const startedAt = Date.now();
    setElapsed(0);
    clearInterval(timerRef.current);
    timerRef.current = setInterval(() => setElapsed(Math.round((Date.now() - startedAt) / 1000)), 1000);

    try {
      logLine(`Starting analysis of ${files.length} report(s) in parallel…`, "start");

      // Each report runs its own pipeline CONCURRENTLY; one failure never aborts the rest.
      const results = new Array(files.length);
      await Promise.all(files.map(async (f, idx) => {
        const rep = await analyzeOne(f, ac.signal);
        results[idx] = rep;
        setReports(results.filter(Boolean));  // incremental
      }));

      results.filter(Boolean).forEach((r) => collected.push(r));
      allFindings = collected.flatMap((r) => r.findings || []);

      if (ac.signal.aborted) {
        logLine("Analysis cancelled — correlation, graph and save skipped.", "err");
        return;
      }

      let corrOut = null, graphOut = null;  // captured for auto-save

      // Correlation is only meaningful across 2+ reports that actually have findings.
      const withFindings = collected.filter((r) => r.findings.length > 0).length;
      if (withFindings >= 2) {
        logLine("Correlating across all reports…");
        try {
          const cRes = await fetchStage(`${API_URL}/correlate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ findings: allFindings }),
          }, ac.signal);
          if (!cRes.ok) throw new Error(`correlate failed (${cRes.status})`);
          const cData = await cRes.json();
          corrOut = cData.correlation || {};
          setCorrelation(corrOut);
          logLine(
            cData.correlation?.related
              ? "✓ Reports are related — correlation complete"
              : "✓ Reports are unrelated — analyzed separately",
            "ok"
          );
        } catch (e) {
          // A failed correlation is NOT evidence that reports are unrelated. Say it failed.
          setCorrelationError(errMsg(e));
          logLine(`✗ Correlation ${errMsg(e)} — not a conclusion, the request errored`, "err");
        }
      } else {
        logLine("Correlation skipped — needs 2+ reports with findings", "info");
      }

      // Build the attack-surface graph from every finding gathered (deterministic backend).
      if (allFindings.length > 0) {
        logLine("Building attack-surface graph…");
        try {
          const gRes = await fetchStage(`${API_URL}/graph`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ findings: allFindings, topology }),
          }, ac.signal);
          if (!gRes.ok) throw new Error(`graph failed (${gRes.status})`);
          const gData = await gRes.json();
          graphOut = gData;
          setGraph(gData);
          logLine(
            `✓ Attack surface: ${Math.max((gData.nodes?.length || 1) - 1, 0)} host(s), ` +
            `${gData.paths?.length || 0} attack path(s) to ${gData.reachable_critical?.length || 0} critical asset(s)`,
            "ok"
          );
        } catch (e) {
          setGraphError(errMsg(e));
          logLine(`✗ Attack-surface graph failed: ${errMsg(e)}`, "err");
        }
      }

      const failed = collected.filter((r) => r.status === "failed").length;
      logLine(
        failed > 0 ? `Analysis finished with ${failed} failed report(s)` : "Analysis finished",
        failed > 0 ? "err" : "done"
      );

      // Auto-save this analysis (with provenance) so it can be reloaded from History later.
      try {
        const sRes = await fetch(`${API_URL}/runs`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ reports: collected, correlation: corrOut, graph: graphOut }),
        });
        if (sRes.ok) { const sd = await sRes.json(); setRunMeta(sd.meta || null); }
        loadRuns();
      } catch { /* best-effort */ }
    } catch (e) {
      const m = errMsg(e);
      if (m !== "cancelled") setError(`${m} — is the backend running on :8000?`);
      logLine(`✗ ${m}`, "err");
    } finally {
      clearInterval(timerRef.current);
      abortRef.current = null;
      setRunning(false);
    }
  }

  function cancelAnalysis() {
    abortRef.current?.abort(new DOMException("cancelled", "AbortError"));
    logLine("Cancelling…", "err");
  }

  async function retryReport(name) {
    const f = files.find((x) => x.name === name);
    if (!f) { setError(`Can't retry "${name}" — re-add the file and run again.`); return; }
    const ac = new AbortController();
    abortRef.current = ac;
    setRunning(true);
    logLine(`Retrying ${name}…`, "start");
    try {
      const rep = await analyzeOne(f, ac.signal);
      setReports((prev) => prev.map((r) => (r.name === name ? rep : r)));
      logLine(`Retry of ${name} finished (${rep.status})`, rep.status === "failed" ? "err" : "done");
    } finally {
      abortRef.current = null;
      setRunning(false);
    }
  }

  async function simulateCut(cut) {
    if (!graph) return;
    setSimCut(cut); setSim(null);
    try {
      const r = await fetch(`${API_URL}/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nodes: graph.nodes, edges: graph.edges, cut }),
      });
      if (!r.ok) throw new Error(`simulate failed (${r.status})`);
      setSim(await r.json());
    } catch (e) {
      setSim({ error: (e && e.message) || "simulate error" });
    }
  }
  function clearSim() { setSim(null); setSimCut(null); }

  async function exportPdf() {
    try {
      const res = await fetch(`${API_URL}/export-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reports, correlation, graph }),
      });
      if (!res.ok) throw new Error(`export failed (${res.status})`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "sentinel-report.pdf";
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(`Export failed: ${(e && e.message) || "error"}`);
    }
  }

  async function loadRun(id) {
    try {
      const r = await fetch(`${API_URL}/runs/${id}`);
      if (!r.ok) return;
      const d = await r.json();
      if (d.error) return;
      setReports(d.reports || []);
      setCorrelation(d.correlation || null);
      setCorrelationError("");
      setGraph(d.graph || null);
      setGraphError(""); setSim(null); setSimCut(null); setError("");
      setRunMeta(d.meta || null);
      setLog([{ text: `Loaded saved analysis ${id}`, kind: "done", t: new Date().toLocaleTimeString() }]);
    } catch { /* ignore */ }
  }

  async function renameRun(r) {
    const label = window.prompt("Rename this analysis:", r.label || (r.names || []).join(", "));
    if (label === null) return;
    try {
      await fetch(`${API_URL}/runs/${r.id}/update`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label }),
      });
      loadRuns();
    } catch { /* best-effort */ }
  }

  async function tagRun(r) {
    const order = ["", "test", "demo"];  // cycle: none -> test -> demo -> none
    const next = order[(order.indexOf(r.tag || "") + 1) % order.length];
    try {
      await fetch(`${API_URL}/runs/${r.id}/update`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tag: next }),
      });
      loadRuns();
    } catch { /* best-effort */ }
  }

  async function deleteRun(id) {
    if (!window.confirm("Delete this saved analysis? This cannot be undone.")) return;
    try {
      await fetch(`${API_URL}/runs/${id}`, { method: "DELETE" });
      loadRuns();
    } catch { /* best-effort */ }
  }

  const okReports = reports.filter((r) => r.status !== "failed");
  const totalFindings = reports.reduce((n, r) => n + (r.findings?.length || 0), 0);
  const failedCount = reports.filter((r) => r.status === "failed").length;
  // A report was security-EVALUATED only if it carries a real scan result.
  const secEvaluated = (r) => r.security && typeof r.security.injection_detected === "boolean";
  const secFlagged = (r) => secEvaluated(r) && (r.security.injection_detected || r.security.output_ok === false);
  const injectionReports = reports.filter((r) => r.security?.injection_detected);
  const flaggedReports = reports.filter(secFlagged);
  const passedReports = reports.filter((r) => secEvaluated(r) && !secFlagged(r));
  const notEvalReports = reports.filter((r) => !secEvaluated(r));
  // Only claim the L3 output check ran if every passed report actually has that result.
  const l3RanForAllPassed = passedReports.length > 0 &&
    passedReports.every((r) => typeof r.security.output_ok === "boolean");
  const related = !!correlation?.related && !correlationError;
  const commonFixes = related ? (correlation?.common_fixes || []) : [];
  const corroboratedItems = correlation?.corroborated || correlation?.confirmed || [];  // back-compat
  const nCorroborated = related ? corroboratedItems.length : 0;
  const nHidden = related ? (correlation?.hidden_risks?.length || 0) : 0;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">🛡️ <span>Sentinel</span></div>
        <div className="brand-sub">Security Digital Twin</div>

        <div className="side-label">Reports</div>
        <div
          className={`drop ${dragging ? "drag" : ""}`}
          role="button"
          tabIndex={0}
          aria-label="Add report files: click, or press Enter to browse"
          onClick={() => inputRef.current?.click()}
          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); inputRef.current?.click(); } }}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); addFiles(e.dataTransfer.files); }}
        >
          <div className="drop-icon">＋</div>
          <div>Drop reports here<br /><span>or click to browse</span></div>
          <input ref={inputRef} type="file" multiple hidden onChange={(e) => addFiles(e.target.files)} />
        </div>

        {files.length > 0 && (
          <div className="file-list">
            {files.map((f) => (
              <div key={f.name} className="file-row">
                <span className="file-name">{f.name}</span>
                <button className="x" aria-label={`Remove ${f.name}`} onClick={() => removeFile(f.name)}>×</button>
              </div>
            ))}
          </div>
        )}

        <div className="side-label">Topology (optional)</div>
        {!topoName ? (
          <button className="topo-add" onClick={() => topoRef.current?.click()}>
            ＋ Add topology JSON <span>for confirmed paths</span>
          </button>
        ) : (
          <div className="file-row">
            <span className="file-name">🗺 {topoName}</span>
            <button className="x" aria-label="Remove topology" onClick={clearTopology}>×</button>
          </div>
        )}
        <input ref={topoRef} type="file" accept=".json,application/json" hidden
          onChange={(e) => loadTopology(e.target.files?.[0])} />

        <div className="side-label">Focus (optional)</div>
        <textarea className="focus" rows={3}
          placeholder="e.g. what are the critical findings?"
          value={message} onChange={(e) => setMessage(e.target.value)} />

        {!running ? (
          <button className="run" onClick={analyze}>▶ Run Analysis</button>
        ) : (
          <div className="run-row">
            <button className="run" disabled>Analyzing… ⏱ {elapsed}s</button>
            <button className="cancel" onClick={cancelAnalysis}>✕ Cancel</button>
          </div>
        )}
        {error && <div className="err-box">{error}</div>}

        {runs.length > 0 && (
          <>
            <div className="side-label hist-label">
              <span>History</span>
              {runs.some((r) => r.tag) && (
                <button className="hist-filter" onClick={() => setHideTagged((v) => !v)}>
                  {hideTagged ? "show all" : "hide test/demo"}
                </button>
              )}
            </div>
            <div className="run-list">
              {(hideTagged ? runs.filter((r) => !r.tag) : runs).slice(0, 10).map((r) => (
                <div key={r.id} className="run-item">
                  <div className="run-open" onClick={() => loadRun(r.id)} title={r.id}>
                    <span className="run-names">
                      {r.label || (r.names || []).join(", ") || "—"}
                      {r.tag && <span className={`run-tag ${r.tag}`}>{r.tag}</span>}
                    </span>
                    <span className="run-meta">{r.reports} report(s) · {r.findings} findings</span>
                  </div>
                  <div className="run-actions">
                    <button title="Rename" onClick={() => renameRun(r)}>✎</button>
                    <button title="Tag (test / demo)" onClick={() => tagRun(r)}>🏷</button>
                    <button title="Delete" onClick={() => deleteRun(r.id)}>🗑</button>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </aside>

      <main className="main">
        <div className="topbar">
          <div className="topbar-left">
            <h1>Analysis Console</h1>
            {reports.length > 0 && !running && (
              <button className="export-btn" onClick={exportPdf}>⬇ Export PDF</button>
            )}
          </div>
          <div className="stat-row">
            <Stat n={reports.length} label="Reports" />
            <Stat n={totalFindings} label="Findings" />
            <Stat n={nCorroborated} label="Corroborated" tone="ok" />
            <Stat n={nHidden} label="Hidden" tone="danger" />
            {injectionReports.length > 0 && <Stat n={injectionReports.length} label="Injection" tone="danger" />}
            {failedCount > 0 && <Stat n={failedCount} label="Failed" tone="danger" />}
          </div>
        </div>

        <div className="panel">
          <div className="panel-head">● Live Activity</div>
          <div className="console">
            {log.length === 0 && <div className="muted">Waiting to run — add reports and click Run Analysis.</div>}
            {log.map((l, i) => (
              <div key={i} className={`ln ${l.kind}`}><span className="ts">{l.t}</span> {l.text}</div>
            ))}
          </div>
        </div>

        {/* Provenance — makes a saved/restored analysis self-describing and auditable. */}
        {runMeta && (
          <div className="panel">
            <div className="panel-head">🧾 Run Provenance</div>
            <div className="prov">
              <div><span className="pk">Analyzed</span> {runMeta.created ? new Date(runMeta.created * 1000).toLocaleString() : "—"}</div>
              <div><span className="pk">Model</span> {runMeta.model}</div>
              <div>
                <span className="pk">Topology</span> {runMeta.topology}
                {runMeta.topology === "inferred" && <span className="muted"> (inferred — assumptions listed in the graph panel)</span>}
              </div>
              <div><span className="pk">Versions</span> scoring v{runMeta.scoring_version} · app v{runMeta.app_version}</div>
              {(runMeta.files || []).length > 0 && (
                <div className="prov-files">
                  <span className="pk">Source files</span>
                  <table className="ptable"><tbody>
                    {runMeta.files.map((f, i) => (
                      <tr key={i}>
                        <td>{f.name}</td>
                        <td className="mono">{f.sha256 ? f.sha256.slice(0, 12) + "…" : "—"}</td>
                        <td>{f.parser ? (f.parser.startsWith("deterministic") ? f.parser.split(":")[1] + " (deterministic)" : "LLM") : "—"}</td>
                        <td>{f.findings} findings</td>
                        <td className={f.security_evaluated ? "prov-ok" : "prov-na"}>
                          {f.security_evaluated ? "✓ security checked" : "• not checked"}
                        </td>
                      </tr>
                    ))}
                  </tbody></table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Guardrails — LLM security. Shows prompt-injection scan results per report. */}
        {reports.length > 0 && (
          <div className="panel">
            <div className="panel-head">🛡️ Guardrails — LLM Security</div>
            <div className="gr-body">
              <div className="gr-summary">
                {passedReports.length > 0 && <span className="grs ok">✓ {passedReports.length} passed</span>}
                {flaggedReports.length > 0 && <span className="grs bad">⚠ {flaggedReports.length} flagged</span>}
                {notEvalReports.length > 0 && <span className="grs na">• {notEvalReports.length} not evaluated</span>}
              </div>

              {flaggedReports.map((r, i) => (
                <div key={i} className="gr-report">
                  <div className="gr-name">
                    📄 {r.name}
                    {r.security.injection_detected && <span className="gr-sev">{r.security.count} injection attempt(s) · {r.security.max_severity}</span>}
                  </div>
                  {(r.security.detections || []).map((d, j) => (
                    <div key={j} className="gr-det">
                      <span className={`gr-tech t-${(d.severity || "").toLowerCase()}`}>{d.technique}</span>
                      <code className="gr-snip">{d.snippet}</code>
                    </div>
                  ))}
                  {r.security.output_ok === false ? (
                    <div className="gr-out fail">⚠ Output check FAILED — {r.security.output_reason}. The model's reply looked suspicious; review this report (possible successful injection).</div>
                  ) : typeof r.security.output_ok === "boolean" ? (
                    <div className="gr-out ok">✓ Output check passed — no sign of hijack or prompt leak in the model's reply.</div>
                  ) : null}
                </div>
              ))}

              {notEvalReports.length > 0 && (
                <div className="gr-note">
                  • {notEvalReports.length} report(s) <b>not evaluated</b> — no scan metadata (an unreadable/empty file, or a run saved before guardrails existed). This is <b>not</b> a pass.
                </div>
              )}

              {flaggedReports.length === 0 && passedReports.length > 0 && (
                <div className="gr-clean">
                  ✓ {passedReports.length} report(s) passed — scanned for injection (L1) and hardened so report text is treated as data not instructions (L2)
                  {l3RanForAllPassed ? "; responses also passed the output check (L3)." : "."}
                </div>
              )}

              {passedReports.length === 0 && flaggedReports.length === 0 && (
                <div className="gr-note">No reports were security-evaluated in this run.</div>
              )}
            </div>
          </div>
        )}

        {/* Prioritized fixes, grouped by report name; correlated fixes last */}
        {okReports.length > 0 && (
          <div className="panel">
            <div className="panel-head">🎯 Prioritized Fixes</div>
            <div className="fixes">
              {okReports.map((r, i) => (
                <div key={i} className="fix-report">
                  <h4>📄 {r.name}</h4>
                  {r.fixesFailed && (
                    <p className="fail-inline">
                      ⚠ Fixes step failed for this report.
                      <button className="retry-btn" onClick={() => retryReport(r.name)} disabled={running}>↻ Retry</button>
                    </p>
                  )}
                  {!r.fixesFailed && r.fixes.length === 0 && <p className="muted">No fixes generated for this report.</p>}
                  <ol>{r.fixes.map((fx, j) => <li key={j}>{fx}</li>)}</ol>
                </div>
              ))}
              {commonFixes.length > 0 && (
                <div className="fix-report common">
                  <h4>🔗 Correlated / Common Fixes</h4>
                  <ol>{commonFixes.map((fx, j) => <li key={j}>{fx}</li>)}</ol>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Cross-tool correlation — only shown once a real correlate result (or failure) exists */}
        {(correlation || correlationError) && (
          <div className="panel">
            <div className="panel-head">🔗 Cross-Tool Correlation</div>
            {correlationError ? (
              <div className="scope unrel">
                <b>Correlation failed</b> — the request errored ({correlationError}). This is <b>not</b> a
                conclusion that the reports are unrelated. Re-run to retry.
              </div>
            ) : (
              <>
                {correlation.scope && (
                  <div className={`scope ${related ? "rel" : "unrel"}`}>
                    <b>{related ? "Related reports" : "Unrelated reports"}</b> — {correlation.scope}
                  </div>
                )}
                {related ? (
                  <>
                    <div className="ev-note">
                      Evidence states: <b>Corroborated</b> = multiple tools agree (not proven exploitable
                      or human-verified). Nothing here is claimed as exploited unless telemetry proves it.
                    </div>
                    <div className="cols">
                      <Corr title="Corroborated" items={corroboratedItems} cls="ok" />
                      <Corr title="Hidden / Chained Risks" items={correlation.hidden_risks} cls="danger" />
                    </div>
                  </>
                ) : (
                  <p className="muted pad">No cross-tool correlation — these reports cover different targets, so each is analyzed separately (see per-report fixes and findings).</p>
                )}
              </>
            )}
          </div>
        )}

        {/* Attack-surface graph + what-if simulation — the Digital Twin core */}
        {graphError && (
          <div className="panel">
            <div className="panel-head">🕸️ Attack Surface</div>
            <div className="fail-box" style={{ margin: 14 }}>⚠ Graph build failed: {graphError}. Re-run to retry.</div>
          </div>
        )}
        {graph && graph.nodes && graph.nodes.length > 1 && (
          <div className="panel">
            <div className="panel-head">🕸️ Attack Surface & What-If Simulation</div>
            <AttackSurface
              graph={graph}
              sim={sim}
              simCut={simCut}
              onSimulate={simulateCut}
              onClear={clearSim}
            />
          </div>
        )}

        {/* Per-report findings + that report's false positives */}
        {reports.length > 0 && (
          <div className="panel">
            <div className="panel-head">📄 Findings by Report</div>
            {reports.map((r, i) => (
              <details key={i} className="report" open={i === reports.length - 1}>
                <summary>
                  {r.name}
                  {r.security?.injection_detected && <span className="count inj">🛡️ injection</span>}
                  {r.status === "failed" && <span className="count fail">failed</span>}
                  {r.status === "empty" && <span className="count empty">no findings</span>}
                  {r.status === "ok" && <span className="count">{r.findings?.length || 0}</span>}
                  {r.parser && (
                    <span className={`count parser ${r.parser.startsWith("deterministic") ? "det" : "llm"}`}>
                      {r.parser.startsWith("deterministic") ? "⚡ " + r.parser.split(":")[1] : "LLM"}
                    </span>
                  )}
                </summary>
                {r.status === "failed" && (
                  <div className="fail-box">
                    ⚠ {r.error}
                    <button className="retry-btn" onClick={() => retryReport(r.name)} disabled={running}>↻ Retry</button>
                  </div>
                )}
                {r.findings?.length > 0 && (
                  <table className="ftable">
                    <tbody>
                      {r.findings.map((f, j) => (
                        <tr key={j}>
                          <td><span className={`sev sev-${(f.severity || "unknown").toLowerCase()}`}>{f.severity || "Unknown"}</span></td>
                          <td className="fname">
                            {f.name}
                            {f.evidence && <div className="eviq">“{f.evidence}”</div>}
                          </td>
                          <td className="fhost">{f.host}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {r.false_positives?.length > 0 && (
                  <div className="fp">
                    <div className="fp-head">⚠️ Likely false positives</div>
                    {r.false_positives.map((fp, k) => (
                      <div key={k} className="fp-item"><b>{fp.finding}</b> — {fp.why}</div>
                    ))}
                  </div>
                )}
              </details>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}

function Stat({ n, label, tone }) {
  return (
    <div className={`stat ${tone || ""}`}>
      <div className="stat-n">{n}</div>
      <div className="stat-l">{label}</div>
    </div>
  );
}

function Corr({ title, items, cls }) {
  return (
    <div className={`corr ${cls}`}>
      <h3>{title} <span className="badge">{items?.length || 0}</span></h3>
      {(!items || items.length === 0) && <p className="muted">None</p>}
      {items?.map((it, i) => (
        <div key={i} className="corr-item">
          <b>{it.summary}</b>
          <div className="meta">{(it.hosts || []).join(", ") || "—"} · {(it.tools || []).join(", ") || "—"}</div>
          <p>{it.why}</p>
        </div>
      ))}
    </div>
  );
}

// Layered left-to-right layout: column = hop distance from Internet, spread vertically.
function computeLayout(graph) {
  const NW = 130, NH = 38, COLW = 185, ROWH = 74, PADX = 74, PADY = 46;
  const adj = {};
  graph.edges.forEach((e) => { (adj[e.source] = adj[e.source] || []).push(e.target); });

  const layer = { Internet: 0 };
  let frontier = ["Internet"];
  while (frontier.length) {
    const next = [];
    frontier.forEach((u) => (adj[u] || []).forEach((v) => {
      if (layer[v] === undefined) { layer[v] = layer[u] + 1; next.push(v); }
    }));
    frontier = next;
  }
  let maxLayer = 0;
  graph.nodes.forEach((n) => { if (layer[n.id] !== undefined) maxLayer = Math.max(maxLayer, layer[n.id]); });
  const orphanLayer = maxLayer + 1;

  const cols = {};
  graph.nodes.forEach((n) => {
    const L = layer[n.id] === undefined ? orphanLayer : layer[n.id];
    (cols[L] = cols[L] || []).push(n.id);
  });
  const colKeys = Object.keys(cols).map(Number);
  const maxRows = Math.max(...colKeys.map((k) => cols[k].length), 1);

  const pos = {};
  colKeys.forEach((L) => {
    const ids = cols[L];
    const colH = (ids.length - 1) * ROWH;
    const startY = PADY + ((maxRows - 1) * ROWH) / 2 - colH / 2;
    ids.forEach((id, i) => { pos[id] = { x: PADX + L * COLW, y: startY + i * ROWH }; });
  });
  const width = PADX * 2 + Math.max(...colKeys, 0) * COLW + NW;
  const height = PADY * 2 + (maxRows - 1) * ROWH + NH;
  return { pos, width, height, NW, NH };
}

function sevColor(s) {
  s = (s || "").toLowerCase();
  if (s === "critical" || s === "high") return "#ef4444";
  if (s === "medium") return "#f59e0b";
  return "#3b82f6";
}

function AttackSurface({ graph, sim, simCut, onSimulate, onClear }) {
  const { pos, width, height, NW, NH } = useMemo(() => computeLayout(graph), [graph]);
  const reachable = new Set(graph.reachable_critical || []);
  const cutKey = simCut ? `${simCut[0]}->${simCut[1]}` : null;
  const cutEdge = simCut ? (graph.edges || []).find((e) => e.source === simCut[0] && e.target === simCut[1]) : null;

  let verdict = null;
  if (sim && !sim.error) {
    const removed = (sim.before.paths?.length || 0) - (sim.after.paths?.length || 0);
    const wasReachable = new Set(sim.before.reachable_critical || []);
    const stillReachable = new Set(sim.after.reachable_critical || []);
    const protectedAssets = [...wasReachable].filter((a) => !stillReachable.has(a));
    verdict = { removed, protectedAssets, stillReachable: [...stillReachable] };
  }

  return (
    <div>
      <div className="assume">
        <b>⚠ Model assumptions</b> — topology is <i>inferred</i>, not proven by the reports. The score
        is a heuristic <b>priority</b> (asset value × path exploit-likelihood), not a breach probability.
        Longer chains score lower because each hop multiplies in an independent exploit likelihood.
        <ul>{(graph.assumptions || []).map((a, i) => <li key={i}>{a}</li>)}</ul>
      </div>

      <div className="graph-scroll">
        <svg width={width} height={height} className="graph-svg" role="img"
          aria-label="Attack-surface graph: Internet on the left, critical assets on the right">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" fill="#64748b" />
            </marker>
          </defs>
          {graph.edges.map((e, i) => {
            const a = pos[e.source], b = pos[e.target];
            if (!a || !b) return null;
            const isCut = cutKey === `${e.source}->${e.target}`;
            const exposure = e.basis === "exposure";
            const x1 = a.x + NW / 2, y1 = a.y, x2 = b.x - NW / 2, y2 = b.y;
            return (
              <g key={i} className="edge" style={{ cursor: "pointer" }} onClick={() => onSimulate([e.source, e.target])}>
                <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="transparent" strokeWidth="16" />
                <line x1={x1} y1={y1} x2={x2} y2={y2}
                  stroke={isCut ? "#475569" : (exposure ? "#64748b" : sevColor(e.severity))}
                  strokeWidth={isCut ? 1.5 : 2.5}
                  strokeDasharray={(isCut || exposure) ? "5 5" : "0"}
                  markerEnd="url(#arrow)" />
                <title>{e.source} → {e.target} · {exposure ? "exposure-only (open service)" : "vuln-backed"} · {e.severity} · via {e.via} · topology {e.topology || "inferred"}{isCut ? " · CUT" : ""} — click to simulate: {e.action}</title>
              </g>
            );
          })}
          {graph.nodes.map((n, i) => {
            const p = pos[n.id]; if (!p) return null;
            const hit = reachable.has(n.id);
            return (
              <g key={i} transform={`translate(${p.x - NW / 2},${p.y - NH / 2})`}>
                <rect width={NW} height={NH} rx="9" className={`gnode k-${n.kind} ${hit ? "hit" : ""}`} />
                <text x={NW / 2} y={NH / 2 + 4} textAnchor="middle" className="gnode-t">
                  {n.id === "Internet" ? "🌐 Internet" : n.id}
                </text>
                {n.criticality > 0 && (
                  <text x={NW - 8} y={13} textAnchor="end" className="gnode-c">C{n.criticality}</text>
                )}
              </g>
            );
          })}
        </svg>
      </div>
      <div className="graph-legend">
        <span><svg width="26" height="8"><line x1="1" y1="4" x2="25" y2="4" stroke="#ef4444" strokeWidth="2.5" /></svg> vuln-backed step (exploitable finding)</span>
        <span><svg width="26" height="8"><line x1="1" y1="4" x2="25" y2="4" stroke="#64748b" strokeWidth="2" strokeDasharray="4 3" /></svg> exposure-only step (open service, no confirmed vuln)</span>
      </div>

      <div className="paths">
        <div className="paths-head">
          Potential paths to critical assets <span className="badge">{graph.paths.length}</span>
          <div className="paths-sub">
            {graph.topology_supplied ? (
              <><b>Confirmed</b> = supplied-topology edges + an exploitable finding at every hop. Others remain hypothetical.</>
            ) : (
              <>All paths are <b>hypothetical</b> — topology is inferred, not supplied. <b>Vuln-backed</b> = an exploitable finding at every hop; <b>exposure-only</b> = includes open-service steps. Upload a topology file for confirmed paths.</>
            )}
          </div>
        </div>
        {graph.paths.length === 0 && (
          <p className="muted">No path from the Internet to a critical asset under the current
            (inferred) topology. Either nothing high-value is exposed, or the reports don't describe
            a reachable chain.</p>
        )}
        {graph.paths.map((pth, i) => (
          <div key={i} className="path-row">
            <span className={`pclass ${pth.path_class}`}>
              {pth.path_class === "confirmed"
                ? "CONFIRMED · topology-verified"
                : pth.path_class === "vuln"
                  ? "HYPOTHETICAL · vuln-backed"
                  : "HYPOTHETICAL · exposure-only"}
            </span>
            <div className="path-line">
              {pth.path.map((h, j) => (
                <span key={j} className="hop">
                  {h === "Internet" ? "🌐 Internet" : h}
                  {j < pth.path.length - 1 && <span className="arr"> → </span>}
                </span>
              ))}
            </div>
            <div className="path-meta">
              <span className="pri">priority {pth.priority}</span>
              <span>likelihood {pth.likelihood}%</span>
              <span>target crit {pth.criticality}/5</span>
            </div>
            <div className="path-cuts">
              {pth.steps.map((s, j) => (
                <button key={j} className={`cutbtn ${s.basis === "exploit" ? "b-exploit" : "b-exposure"}`}
                  onClick={() => onSimulate([s.from, s.to])} title={`Simulate: ${s.action}`}>
                  ✂ {s.action || `${s.from} → ${s.to}`}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>

      {sim && (
        <div className="simbox">
          {sim.error ? (
            <div className="fail-box">Simulation failed: {sim.error}</div>
          ) : (
            <>
              <div className="sim-head">
                🧪 What-if: <b>{cutEdge?.action || `${simCut[0]} → ${simCut[1]}`}</b>
                <button className="linkbtn" onClick={onClear}>clear</button>
              </div>
              <div className="sim-cols">
                <div className="sim-side">
                  <div className="sim-label">Before</div>
                  <div>Reachable critical assets: <b>{sim.before.reachable_critical.length ? sim.before.reachable_critical.join(", ") : "none"}</b></div>
                  <div>Attack paths: <b>{sim.before.paths.length}</b></div>
                </div>
                <div className="sim-side after">
                  <div className="sim-label">After</div>
                  <div>Reachable critical assets: <b>{sim.after.reachable_critical.length ? sim.after.reachable_critical.join(", ") : "none"}</b></div>
                  <div>Attack paths: <b>{sim.after.paths.length}</b></div>
                </div>
              </div>
              {verdict && (
                <div className={`sim-verdict ${verdict.protectedAssets.length ? "good" : ""}`}>
                  {verdict.protectedAssets.length > 0
                    ? `✓ This fix protects ${verdict.protectedAssets.join(", ")} — no longer reachable from the Internet. Removes ${verdict.removed} attack path(s).`
                    : verdict.removed > 0
                      ? `Removes ${verdict.removed} attack path(s), but critical assets stay reachable via other routes${verdict.stillReachable.length ? " (" + verdict.stillReachable.join(", ") + ")" : ""}. Defence-in-depth needed.`
                      : "No change — this edge isn't on any current attack path."}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
