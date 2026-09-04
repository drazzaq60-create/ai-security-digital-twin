"use client";

import { useState, useRef, useMemo } from "react";

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
    setGraph(null); setGraphError(""); setSim(null); setSimCut(null);
    const collected = [];
    const allFindings = [];

    try {
      logLine(`Starting analysis of ${files.length} report(s) in parallel…`, "start");

      // Each report runs as an independent pipeline (extract -> fixes) CONCURRENTLY.
      // One failure never aborts the others; the backend handles the parallel requests.
      const results = new Array(files.length);
      const commit = () => setReports(results.filter(Boolean));

      await Promise.all(files.map(async (f, idx) => {
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
            results[idx] = rep; commit(); return;
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
          results[idx] = rep; commit(); return;
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

        results[idx] = rep; commit();
      }));

      results.filter(Boolean).forEach((r) => collected.push(r));

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

      // Build the attack-surface graph from every finding gathered (deterministic backend).
      if (allFindings.length > 0) {
        logLine("Building attack-surface graph…");
        try {
          const gRes = await fetch(`${API_URL}/graph`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ findings: allFindings }),
          });
          if (!gRes.ok) throw new Error(`graph failed (${gRes.status})`);
          const gData = await gRes.json();
          setGraph(gData);
          logLine(
            `✓ Attack surface: ${Math.max((gData.nodes?.length || 1) - 1, 0)} host(s), ` +
            `${gData.paths?.length || 0} attack path(s) to ${gData.reachable_critical?.length || 0} critical asset(s)`,
            "ok"
          );
        } catch (e) {
          setGraphError((e && e.message) || "graph error");
          logLine(`✗ Attack-surface graph failed: ${(e && e.message) || "error"}`, "err");
        }
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
            const x1 = a.x + NW / 2, y1 = a.y, x2 = b.x - NW / 2, y2 = b.y;
            return (
              <g key={i} className="edge" style={{ cursor: "pointer" }} onClick={() => onSimulate([e.source, e.target])}>
                <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="transparent" strokeWidth="16" />
                <line x1={x1} y1={y1} x2={x2} y2={y2}
                  stroke={isCut ? "#475569" : sevColor(e.severity)}
                  strokeWidth={isCut ? 1.5 : 2.5}
                  strokeDasharray={isCut ? "5 5" : "0"}
                  markerEnd="url(#arrow)" />
                <title>{e.source} → {e.target} · {e.severity} · via {e.via}{e.assumed ? " · assumed" : ""}{isCut ? " · CUT" : ""} — click to simulate patching this</title>
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

      <div className="paths">
        <div className="paths-head">
          Attack paths to critical assets <span className="badge">{graph.paths.length}</span>
        </div>
        {graph.paths.length === 0 && (
          <p className="muted">No path from the Internet to a critical asset under the current
            (assumed) topology. Either nothing high-value is exposed, or the reports don't describe
            a reachable chain.</p>
        )}
        {graph.paths.map((pth, i) => (
          <div key={i} className="path-row">
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
                <button key={j} className="cutbtn" onClick={() => onSimulate([s.from, s.to])}>
                  ✂ patch {s.from === "Internet" ? "🌐" : s.from} → {s.to}
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
                🧪 What-if: patch <b>{simCut[0] === "Internet" ? "🌐 Internet" : simCut[0]} → {simCut[1]}</b>
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
