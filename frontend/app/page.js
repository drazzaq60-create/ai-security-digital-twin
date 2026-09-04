"use client";

import { useState, useRef } from "react";

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
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);

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

  async function analyze() {
    if (files.length === 0) { setError("Add at least one report file."); return; }
    setError(""); setRunning(true); setLog([]); setReports([]);
    setCorrelation(null); setCorrelationError("");
    const collected = [];
    const allFindings = [];

    try {
      logLine(`Starting analysis of ${files.length} report(s)…`, "start");

      for (const f of files) {
        // Each report is independent: one failure must NOT abort the whole run.
        const rep = {
          name: f.name, findings: [], fixes: [], false_positives: [],
          status: "ok", error: "", fixesFailed: false,
        };

        logLine(`Extracting findings from ${f.name}…`);
        try {
          const form = new FormData();
          form.append("file", f);
          const eRes = await fetch(`${API_URL}/extract`, { method: "POST", body: form });
          if (!eRes.ok) throw new Error(`extract failed (${eRes.status})`);
          const eData = await eRes.json();
          rep.name = eData.name || f.name;

          if (eData.error) {
            rep.status = "failed"; rep.error = eData.error;
            logLine(`✗ ${rep.name}: ${eData.error}`, "err");
            collected.push(rep); setReports([...collected]); continue;
          }
          rep.findings = eData.findings || [];
          if (rep.findings.length === 0) {
            rep.status = "empty";
            logLine(`• ${rep.name}: no findings extracted`, "info");
          } else {
            logLine(`✓ ${rep.name}: ${rep.findings.length} findings`, "ok");
          }
        } catch (e) {
          rep.status = "failed"; rep.error = (e && e.message) || "extract error";
          logLine(`✗ ${rep.name}: ${rep.error}`, "err");
          collected.push(rep); setReports([...collected]); continue;
        }

        // Per-report fixes — only if this report actually produced findings.
        if (rep.findings.length > 0) {
          logLine(`Analyzing ${rep.name} (fixes + false positives)…`);
          try {
            const rRes = await fetch(`${API_URL}/report-fixes`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ name: rep.name, findings: rep.findings, focus: message }),
            });
            if (!rRes.ok) throw new Error(`fixes failed (${rRes.status})`);
            const rData = await rRes.json();
            rep.fixes = rData.fixes || [];
            rep.false_positives = rData.false_positives || [];
          } catch (e) {
            rep.fixesFailed = true;
            logLine(`✗ ${rep.name}: fixes step failed (${(e && e.message) || "error"})`, "err");
          }
          allFindings.push(...rep.findings);
        }

        collected.push(rep); setReports([...collected]);
      }

      // Correlation is only meaningful across 2+ reports that actually have findings.
      const withFindings = collected.filter((r) => r.findings.length > 0).length;
      if (withFindings >= 2) {
        logLine("Correlating across all reports…");
        try {
          const cRes = await fetch(`${API_URL}/correlate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ findings: allFindings }),
          });
          if (!cRes.ok) throw new Error(`correlate failed (${cRes.status})`);
          const cData = await cRes.json();
          setCorrelation(cData.correlation || {});
          logLine(
            cData.correlation?.related
              ? "✓ Reports are related — correlation complete"
              : "✓ Reports are unrelated — analyzed separately",
            "ok"
          );
        } catch (e) {
          // A failed correlation is NOT evidence that reports are unrelated. Say it failed.
          setCorrelationError((e && e.message) || "correlate error");
          logLine(`✗ Correlation failed — not a conclusion, the request errored`, "err");
        }
      } else {
        logLine("Correlation skipped — needs 2+ reports with findings", "info");
      }

      const failed = collected.filter((r) => r.status === "failed").length;
      logLine(
        failed > 0 ? `Analysis finished with ${failed} failed report(s)` : "Analysis finished",
        failed > 0 ? "err" : "done"
      );
    } catch (e) {
      const m = (e && e.message) || "error";
      setError(`${m} — is the backend running on :8000?`);
      logLine(`✗ ${m}`, "err");
    } finally {
      setRunning(false);
    }
  }

  const okReports = reports.filter((r) => r.status !== "failed");
  const totalFindings = reports.reduce((n, r) => n + (r.findings?.length || 0), 0);
  const failedCount = reports.filter((r) => r.status === "failed").length;
  const related = !!correlation?.related && !correlationError;
  const commonFixes = related ? (correlation?.common_fixes || []) : [];
  const nConfirmed = related ? (correlation?.confirmed?.length || 0) : 0;
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

        <div className="side-label">Focus (optional)</div>
        <textarea className="focus" rows={3}
          placeholder="e.g. what are the critical findings?"
          value={message} onChange={(e) => setMessage(e.target.value)} />

        <button className="run" onClick={analyze} disabled={running}>
          {running ? "Analyzing…" : "▶ Run Analysis"}
        </button>
        {error && <div className="err-box">{error}</div>}
      </aside>

      <main className="main">
        <div className="topbar">
          <h1>Analysis Console</h1>
          <div className="stat-row">
            <Stat n={reports.length} label="Reports" />
            <Stat n={totalFindings} label="Findings" />
            <Stat n={nConfirmed} label="Confirmed" tone="ok" />
            <Stat n={nHidden} label="Hidden" tone="danger" />
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

        {/* Prioritized fixes, grouped by report name; correlated fixes last */}
        {okReports.length > 0 && (
          <div className="panel">
            <div className="panel-head">🎯 Prioritized Fixes</div>
            <div className="fixes">
              {okReports.map((r, i) => (
                <div key={i} className="fix-report">
                  <h4>📄 {r.name}</h4>
                  {r.fixesFailed && <p className="fail-inline">⚠ Fixes step failed for this report — re-run to retry.</p>}
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
                  <div className="cols">
                    <Corr title="Confirmed" items={correlation.confirmed} cls="ok" />
                    <Corr title="Hidden / Chained Risks" items={correlation.hidden_risks} cls="danger" />
                  </div>
                ) : (
                  <p className="muted pad">No cross-tool correlation — these reports cover different targets, so each is analyzed separately (see per-report fixes and findings).</p>
                )}
              </>
            )}
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
                  {r.status === "failed" && <span className="count fail">failed</span>}
                  {r.status === "empty" && <span className="count empty">no findings</span>}
                  {r.status === "ok" && <span className="count">{r.findings?.length || 0}</span>}
                </summary>
                {r.status === "failed" && <div className="fail-box">⚠ {r.error}</div>}
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
