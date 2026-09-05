"use client";

import { useState, useRef, useMemo, useEffect } from "react";

// Configurable so a deployed build can point at a real backend, not the visitor's own PC.
const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const TOPOLOGY_TEMPLATE = {
  _comment: "Topology = which asset can reach which (from your network/firewall knowledge; no scanner produces this). control: firewall | network | service | port | trust | identity | permission.",
  assets: { db01: { criticality: 5 } },
  edges: [
    { from: "internet", to: "web01", control: "firewall" },
    { from: "web01", to: "db01", control: "service" },
  ],
};
const TEMPLATE_TEXT = JSON.stringify(TOPOLOGY_TEMPLATE, null, 2);

const RAIL = [
  { id: "scan", label: "Scan" },
  { id: "overview", label: "Overview" },
  { id: "paths", label: "Attack Paths" },
  { id: "findings", label: "Findings" },
  { id: "mitre", label: "ATT&CK" },
  { id: "summary", label: "Summary" },
  { id: "compare", label: "Compare" },
  { id: "history", label: "History" },
];
const VIEW_TITLES = {
  scan: "New Scan", overview: "Overview", paths: "Attack Paths",
  findings: "Findings & Correlation", mitre: "MITRE ATT&CK Mapping",
  summary: "Executive Summary", compare: "Compare Analyses", history: "Saved Analyses",
};

function RailIcon({ name }) {
  const p = { fill: "none", stroke: "currentColor", strokeWidth: 1.7, strokeLinecap: "round", strokeLinejoin: "round" };
  const paths = {
    scan: <><circle cx="11" cy="11" r="7" {...p} /><path d="M11 4v7l4.5 4.5" {...p} /></>,
    overview: <><rect x="3" y="3" width="7" height="7" rx="1.5" {...p} /><rect x="12" y="3" width="7" height="7" rx="1.5" {...p} /><rect x="3" y="12" width="7" height="7" rx="1.5" {...p} /><rect x="12" y="12" width="7" height="7" rx="1.5" {...p} /></>,
    paths: <><circle cx="4" cy="11" r="2.2" {...p} /><circle cx="18" cy="5" r="2.2" {...p} /><circle cx="18" cy="17" r="2.2" {...p} /><path d="M6 10 16 6M6 12l10 4" {...p} /></>,
    findings: <><path d="M4 6h14M4 11h14M4 16h9" {...p} /><circle cx="18" cy="17" r="0.6" {...p} /></>,
    compare: <><rect x="3" y="4" width="7" height="14" rx="1.5" {...p} /><rect x="12" y="4" width="7" height="14" rx="1.5" {...p} /></>,
    mitre: <><circle cx="11" cy="11" r="5" {...p} /><path d="M11 1.5v3M11 17.5v3M1.5 11h3M17.5 11h3" {...p} /></>,
    summary: <><path d="M5 3h9l4 4v12a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" {...p} /><path d="M7.5 11h7M7.5 14.5h7M7.5 7.5h3" {...p} /></>,
    history: <><circle cx="11" cy="11" r="7.5" {...p} /><path d="M11 6.5V11l3 2" {...p} /></>,
  };
  return <svg viewBox="0 0 22 22" width="18" height="18" aria-hidden="true">{paths[name]}</svg>;
}

// Deterministic finding -> MITRE ATT&CK technique mapping (keyword/type rules; no LLM).
const MITRE_RULES = [
  { kw: ["sql injection", "sqli"], id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  { kw: ["path traversal", "directory traversal", "lfi", "file inclusion"], id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  { kw: ["rce", "remote code execution", "code execution", "deserial", "ghostcat", "ajp"], id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  { kw: ["cross-site scripting", "cross site scripting", "xss"], id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
  { kw: ["default credential", "default password", "weak password", "weak credential", "valid account"], id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
  { kw: ["privilege escalation", "privesc", "priv esc"], id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  { kw: ["idor", "broken access control", "authorization", "authorisation", "access control"], id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  { kw: ["brute force", "authentication failure", "multiple authentication", "password spray"], id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  { kw: ["ssh"], id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
  { kw: ["tls", "ssl", "cipher", "certificate", "rc4"], id: "T1040", name: "Network Sniffing", tactic: "Collection" },
  { kw: ["csrf", "anti-csrf"], id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  { kw: ["banner", "version disclosure", "username enum", "enumeration"], id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
  { kw: ["outdated", "cve-", "vulnerable"], id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
];
const TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection",
  "Exfiltration", "Impact", "Unmapped"];

function mapFinding(f) {
  const type = (f.type || "").toLowerCase();
  const text = ((f.name || "") + " " + (f.evidence || "")).toLowerCase();
  if (type === "service") return { id: "T1133", name: "External Remote Services", tactic: "Initial Access" };
  for (const rule of MITRE_RULES) if (rule.kw.some((k) => text.includes(k))) return rule;
  if (type === "alert") return { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" };
  return { id: "—", name: "Unmapped", tactic: "Unmapped" };
}

function mitreMap(findings) {
  const tactics = {};
  findings.forEach((f) => {
    const m = mapFinding(f);
    const tac = (tactics[m.tactic] = tactics[m.tactic] || {});
    const tech = (tac[m.id] = tac[m.id] || { id: m.id, name: m.name, items: [] });
    tech.items.push(f);
  });
  return tactics;
}

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
  const [showTemplate, setShowTemplate] = useState(false);
  const inputRef = useRef(null);
  const topoRef = useRef(null);

  async function loadTopology(file) {
    if (!file) return;
    try {
      const text = await file.text();
      const obj = JSON.parse(text);
      if (!obj || !Array.isArray(obj.edges)) throw new Error("missing an \"edges\" array");
      setTopology(obj); setTopoName(file.name); setError("");
      // Apply it right away if an analysis already ran (rebuild only the graph, no re-extraction).
      if (reports.some((r) => (r.findings || []).length)) {
        logLine(`Applying topology "${file.name}" — rebuilding graph…`, "info");
        rebuildGraph(obj);
      }
    } catch (e) {
      setTopology(null); setTopoName("");
      setError(`Topology file invalid: ${(e && e.message) || "not JSON"}. Expected {"edges":[{"from","to","control"}]}.`);
    }
  }
  function clearTopology() { setTopology(null); setTopoName(""); if (topoRef.current) topoRef.current.value = ""; }

  function downloadJson(obj, filename) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  }

  function downloadTemplate() { downloadJson(TOPOLOGY_TEMPLATE, "topology-template.json"); }
  async function copyTemplate() {
    try { await navigator.clipboard.writeText(TEMPLATE_TEXT); logLine("Topology template copied to clipboard", "ok"); }
    catch { setError("Copy failed — select the text in the box and copy manually."); }
  }

  // Rebuild ONLY the graph (no re-extraction) using the given topology — instant.
  async function rebuildGraph(topo) {
    const allFindings = reports.flatMap((r) => r.findings || []);
    if (!allFindings.length) return;
    try {
      const gRes = await fetch(`${API_URL}/graph`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findings: allFindings, topology: topo }),
      });
      if (gRes.ok) {
        const g = await gRes.json();
        setGraph(g); setGraphError(""); setSim(null); setSimCut(null);
        logLine(`✓ Graph rebuilt with ${topo ? "supplied" : "inferred"} topology: ${g.paths?.length || 0} path(s)`, "ok");
      }
    } catch { /* best-effort */ }
  }

  // Auto-draft a topology from the hosts found in the reports (Internet -> web -> app -> db).
  // Suggested/inferred, not confirmed — the user reviews and can edit it.
  function suggestTopology() {
    const nodes = (graph?.nodes || []).filter((n) => n.id !== "Internet");
    if (nodes.length === 0) { setError("Run an analysis first — then I can suggest a topology from the findings."); return; }
    const web = nodes.filter((n) => n.kind === "web").map((n) => n.id);
    const db = nodes.filter((n) => n.kind === "database").map((n) => n.id);
    const other = nodes.filter((n) => n.kind !== "web" && n.kind !== "database").map((n) => n.id);
    let entry = web;
    if (entry.length === 0) entry = nodes.filter((n) => n.internet_facing).map((n) => n.id);
    if (entry.length === 0) entry = [nodes[0].id];

    const edges = [];
    const seen = new Set();
    const addE = (f, t, c) => { const k = f + ">" + t; if (f !== t && !seen.has(k)) { seen.add(k); edges.push({ from: f, to: t, control: c }); } };
    entry.forEach((w) => addE("internet", w, "firewall"));
    entry.forEach((w) => { other.forEach((o) => addE(w, o, "service")); db.forEach((d) => addE(w, d, "service")); });
    other.forEach((o) => db.forEach((d) => addE(o, d, "service")));

    const assets = {};
    nodes.forEach((n) => { if (n.criticality) assets[n.id] = { criticality: n.criticality }; });
    const topo = {
      _comment: "SUGGESTED from report findings — connections are inferred, not confirmed. Review and edit before trusting the paths.",
      assets, edges,
    };
    setTopology(topo); setTopoName("suggested-topology.json"); setError("");
    logLine(`Suggested a topology: ${edges.length} connection(s) across ${nodes.length} asset(s). Rebuilding graph…`, "info");
    rebuildGraph(topo);
  }
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

  const [backendUp, setBackendUp] = useState(null);  // null=unknown, true/false
  const [nav, setNav] = useState("scan");
  const [railOpen, setRailOpen] = useState(true);
  const [scanMode, setScanMode] = useState("manual");  // manual (report upload) | auto (live scan)
  const [scanTarget, setScanTarget] = useState("");
  const [scanPorts, setScanPorts] = useState(true);
  const [scanAuthorized, setScanAuthorized] = useState(false);
  const [cmpA, setCmpA] = useState("");
  const [cmpB, setCmpB] = useState("");
  const [cmpResult, setCmpResult] = useState(null);
  const [execSummary, setExecSummary] = useState("");
  const [execLoading, setExecLoading] = useState(false);

  async function generateSummary() {
    if (reports.length === 0) return;
    setExecLoading(true);
    try {
      const r = await fetch(`${API_URL}/exec-summary`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reports, correlation, graph }),
      });
      if (!r.ok) throw new Error(`summary failed (${r.status})`);
      const d = await r.json();
      setExecSummary(d.summary || "");
    } catch (e) {
      setExecSummary(`Could not generate summary: ${(e && e.message) || "error"}`);
    } finally {
      setExecLoading(false);
    }
  }

  async function runCompare(a, b) {
    if (!a || !b || a === b) { setCmpResult(null); return; }
    try {
      const [ra, rb] = await Promise.all([
        fetch(`${API_URL}/runs/${a}`).then((r) => r.json()),
        fetch(`${API_URL}/runs/${b}`).then((r) => r.json()),
      ]);
      const key = (f) => `${(f.name || "").toLowerCase()}@@${(f.host || "").toLowerCase()}`;
      const mapA = new Map(); (ra.reports || []).flatMap((r) => r.findings || []).forEach((f) => mapA.set(key(f), f));
      const mapB = new Map(); (rb.reports || []).flatMap((r) => r.findings || []).forEach((f) => mapB.set(key(f), f));
      const fixed = [...mapA.values()].filter((f) => !mapB.has(key(f)));   // present before, gone after
      const added = [...mapB.values()].filter((f) => !mapA.has(key(f)));   // new in the later run
      const common = [...mapB.values()].filter((f) => mapA.has(key(f)));
      setCmpResult({ fixed, added, common });
    } catch { setCmpResult({ error: "Could not load those analyses to compare." }); }
  }

  async function loadRuns() {
    try {
      const r = await fetch(`${API_URL}/runs`);
      if (r.ok) { const d = await r.json(); setRuns(d.runs || []); }
    } catch { /* history is best-effort */ }
  }
  async function pingHealth() {
    try {
      const r = await fetch(`${API_URL}/health`, { cache: "no-store" });
      setBackendUp(r.ok);
    } catch { setBackendUp(false); }
  }
  useEffect(() => {
    loadRuns(); pingHealth();
    const t = setInterval(pingHealth, 30000);
    return () => clearInterval(t);
  }, []);

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

  // Shared downstream: correlation (2+ reports) -> attack graph -> auto-save -> Overview.
  // Reused by analyze() (uploads) and runScan() (live scan) so both paths behave identically.
  async function finishPipeline(collected, signal) {
    const allFindings = collected.flatMap((r) => r.findings || []);
    let corrOut = null, graphOut = null;

    const withFindings = collected.filter((r) => (r.findings || []).length > 0).length;
    if (withFindings >= 2) {
      logLine("Correlating across all reports…");
      try {
        const cRes = await fetchStage(`${API_URL}/correlate`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ findings: allFindings }),
        }, signal);
        if (!cRes.ok) throw new Error(`correlate failed (${cRes.status})`);
        const cData = await cRes.json();
        corrOut = cData.correlation || {};
        setCorrelation(corrOut);
        logLine(cData.correlation?.related
          ? "✓ Reports are related — correlation complete"
          : "✓ Reports are unrelated — analyzed separately", "ok");
      } catch (e) {
        setCorrelationError(errMsg(e));
        logLine(`✗ Correlation ${errMsg(e)} — not a conclusion, the request errored`, "err");
      }
    } else {
      logLine("Correlation skipped — needs 2+ reports with findings", "info");
    }

    if (allFindings.length > 0) {
      logLine("Building attack-surface graph…");
      try {
        const gRes = await fetchStage(`${API_URL}/graph`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ findings: allFindings, topology }),
        }, signal);
        if (!gRes.ok) throw new Error(`graph failed (${gRes.status})`);
        const gData = await gRes.json();
        graphOut = gData;
        setGraph(gData);
        logLine(
          `✓ Attack surface: ${Math.max((gData.nodes?.length || 1) - 1, 0)} host(s), ` +
          `${gData.paths?.length || 0} attack path(s) to ${gData.reachable_critical?.length || 0} critical asset(s)`,
          "ok");
      } catch (e) {
        setGraphError(errMsg(e));
        logLine(`✗ Attack-surface graph failed: ${errMsg(e)}`, "err");
      }
    }

    const failed = collected.filter((r) => r.status === "failed").length;
    logLine(failed > 0 ? `Analysis finished with ${failed} failed report(s)` : "Analysis finished",
      failed > 0 ? "err" : "done");

    try {
      const sRes = await fetch(`${API_URL}/runs`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reports: collected, correlation: corrOut, graph: graphOut }),
      });
      if (sRes.ok) { const sd = await sRes.json(); setRunMeta(sd.meta || null); }
      loadRuns();
    } catch { /* best-effort */ }
    setNav("overview");
  }

  // Automatic scan: hit /scan for one authorized target, then run the shared pipeline.
  async function runScan() {
    const target = scanTarget.trim();
    if (!target) { setError("Enter a target (hostname or URL)."); return; }
    if (!scanAuthorized) { setError("Confirm you're authorized to scan this target."); return; }
    setError(""); setRunning(true); setLog([]); setReports([]);
    setCorrelation(null); setCorrelationError("");
    setGraph(null); setGraphError(""); setSim(null); setSimCut(null); setRunMeta(null); setExecSummary("");

    const ac = new AbortController();
    abortRef.current = ac;
    const startedAt = Date.now();
    setElapsed(0);
    clearInterval(timerRef.current);
    timerRef.current = setInterval(() => setElapsed(Math.round((Date.now() - startedAt) / 1000)), 1000);

    try {
      logLine(`Scanning ${target} — TLS, security headers${scanPorts ? ", common ports" : ""}…`, "start");
      const res = await fetchStage(`${API_URL}/scan`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, ports: scanPorts }),
      }, ac.signal);
      if (!res.ok) throw new Error(`scan failed (${res.status})`);
      const data = await res.json();
      if (data.error) { setError(data.error); logLine(`✗ ${data.error}`, "err"); return; }

      const rep = {
        name: data.name, findings: data.findings || [], fixes: [], false_positives: [],
        status: (data.findings || []).length ? "ok" : "empty", error: "", fixesFailed: false,
        security: null, parser: data.parser, sha256: data.sha256, scan: data.scan,
      };
      logLine(`✓ ${rep.name}: ${rep.findings.length} finding(s) in ${data.scan?.duration_s ?? "?"}s`, "ok");
      setReports([rep]);

      // Prioritized fixes for the scan's findings (same LLM step uploads get).
      if (rep.findings.length > 0) {
        logLine("Analyzing findings (fixes + false positives)… waiting for model");
        try {
          const rRes = await fetchStage(`${API_URL}/report-fixes`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: rep.name, findings: rep.findings, focus: message }),
          }, ac.signal);
          if (rRes.ok) { const rData = await rRes.json(); rep.fixes = rData.fixes || []; rep.false_positives = rData.false_positives || []; }
        } catch (e) { rep.fixesFailed = true; logLine(`✗ fixes step failed (${errMsg(e)})`, "err"); }
        setReports([rep]);
      }

      if (ac.signal.aborted) { logLine("Scan cancelled.", "err"); return; }
      await finishPipeline([rep], ac.signal);
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
    setGraph(null); setGraphError(""); setSim(null); setSimCut(null); setRunMeta(null); setExecSummary("");
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

      await finishPipeline(collected, ac.signal);
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
        body: JSON.stringify({ reports, correlation, graph, exec_summary: execSummary }),
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
      setNav("overview");
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
    <div className="shell">
      <nav className={`rail ${railOpen ? "" : "collapsed"}`}>
        <button className="rail-toggle" onClick={() => setRailOpen((o) => !o)} title={railOpen ? "Collapse sidebar" : "Expand sidebar"}>{railOpen ? "«" : "»"}</button>
        <div className="rail-logo">
          <svg className="rl-icon" viewBox="0 0 24 24" aria-hidden="true">
            <defs><linearGradient id="sg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#22c1e8" /><stop offset="1" stopColor="#0369a1" /></linearGradient></defs>
            <path d="M12 2 20 5 V11 C20 16.5 16.5 20.6 12 22 C7.5 20.6 4 16.5 4 11 V5 Z" fill="url(#sg)" />
            <path d="M8.4 12 L11 14.6 L16 8.6" fill="none" stroke="#fff" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div className="rl-txt">
            <div className="rl-word">SENTINEL</div>
            <div className="rl-tag">Security Console</div>
          </div>
        </div>
        {RAIL.map((it) => {
          const enabled = it.id === "scan" || it.id === "history"
            || (it.id === "compare" ? runs.length >= 2 : reports.length > 0);
          return (
            <button key={it.id} disabled={!enabled}
              className={`rail-item ${nav === it.id ? "active" : ""} ${!enabled ? "locked" : ""}`}
              title={!enabled ? (it.id === "compare" ? "Needs 2 saved analyses" : "Run a scan first") : ""}
              onClick={() => enabled && setNav(it.id)}>
              <RailIcon name={it.id} /><span>{it.label}</span>
              {!enabled && <span className="lock">🔒</span>}
            </button>
          );
        })}
        <div className="rail-foot">Sentinel Security</div>
      </nav>

      <main className="workspace">
        <header className="ws-head">
          <h1>{VIEW_TITLES[nav]}</h1>
          <div className="ws-actions">
            {reports.length > 0 && !running && <button className="export-btn" onClick={exportPdf}>⬇ Export PDF</button>}
          </div>
        </header>
        <div className={`ws-body ${nav === "scan" ? "scan" : ""}`}>

      {nav === "scan" && (
      <div className="scanview">
        <div className="scan-modes">
          <button className={`smode ${scanMode === "manual" ? "active" : ""}`} onClick={() => setScanMode("manual")}>📄 Manual — report upload</button>
          <button className={`smode ${scanMode === "auto" ? "active" : ""}`} onClick={() => setScanMode("auto")}>📡 Automatic — live scan</button>
        </div>
        {scanMode === "manual" ? (
        <div className="scan-grid">
        <aside className="sidebar">
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
        <div className="topo-note">
          No scanner outputs this — it maps which assets can reach which (from your
          network/firewall knowledge). Paths that use it become <b>Confirmed</b>.
          <div className="topo-links">
            <button className="linklike" onClick={() => setShowTemplate((v) => !v)}>{showTemplate ? "Hide template" : "View template"}</button>
            {graph?.nodes?.length > 1 && <button className="linklike" onClick={suggestTopology}>Suggest from reports</button>}
            {topoName && <button className="linklike" onClick={() => downloadJson(topology, topoName)}>Download current</button>}
          </div>
          {showTemplate && (
            <div className="tmpl-box">
              <pre>{TEMPLATE_TEXT}</pre>
              <div className="tmpl-actions">
                <button className="linklike" onClick={copyTemplate}>Copy</button>
                <button className="linklike" onClick={downloadTemplate}>Download .json</button>
              </div>
            </div>
          )}
        </div>
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

      </aside>
        <div className="panel logpanel">
        <div className="panel-head">● Live Activity</div>
        <div className="console">
          {log.length === 0 && <div className="muted">Add reports on the left, then Run Analysis — results open in Overview.</div>}
          {log.map((l, i) => (
            <div key={i} className={`ln ${l.kind}`}><span className="ts">{l.t}</span> {l.text}</div>
          ))}
        </div>
      </div>
        </div>
        ) : (
        <div className="scan-grid">
        <aside className="sidebar">
          <div className="side-label">Target</div>
          <input
            className="scan-input"
            placeholder="example.com  or  https://host:8443"
            value={scanTarget}
            onChange={(e) => setScanTarget(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && !running) runScan(); }}
          />

          <label className="scan-check">
            <input type="checkbox" checked={scanPorts} onChange={(e) => setScanPorts(e.target.checked)} />
            <span>Probe common ports (FTP, SSH, RDP, DB, …)</span>
          </label>

          <label className="scan-check auth">
            <input type="checkbox" checked={scanAuthorized} onChange={(e) => setScanAuthorized(e.target.checked)} />
            <span>I'm <b>authorized</b> to scan this target.</span>
          </label>

          <div className="side-label">Focus (optional)</div>
          <textarea className="focus" rows={3}
            placeholder="e.g. what are the critical findings?"
            value={message} onChange={(e) => setMessage(e.target.value)} />

          {!running ? (
            <button className="run" onClick={runScan} disabled={!scanAuthorized}>▶ Run Scan</button>
          ) : (
            <div className="run-row">
              <button className="run" disabled>Scanning… ⏱ {elapsed}s</button>
              <button className="cancel" onClick={cancelAnalysis}>✕ Cancel</button>
            </div>
          )}
          {error && <div className="err-box">{error}</div>}

          <div className="topo-note" style={{ marginTop: 14 }}>
            Light, non-intrusive check — TLS/cert, HTTP security headers, and common-port
            reachability. No exploitation or fuzzing. Results flow into the same pipeline as
            uploads. For deep scans (Nmap/Nessus/ZAP), run them externally and add the reports
            under <b>Manual</b>.
          </div>
        </aside>
        <div className="panel logpanel">
          <div className="panel-head">● Live Activity</div>
          <div className="console">
            {log.length === 0 && <div className="muted">Enter an authorized target on the left, then Run Scan — results open in Overview.</div>}
            {log.map((l, i) => (
              <div key={i} className={`ln ${l.kind}`}><span className="ts">{l.t}</span> {l.text}</div>
            ))}
          </div>
        </div>
        </div>
        )}
      </div>
      )}

      {nav === "overview" && reports.length === 0 && (
        <div className="empty">No analysis yet. <button className="linklike" onClick={() => setNav("scan")}>Start a scan →</button></div>
      )}

      {nav === "overview" && reports.length > 0 && (
        <div className="stat-row">
          <Stat n={reports.length} label="Reports" />
          <Stat n={totalFindings} label="Findings" />
          <Stat n={nCorroborated} label="Corroborated" tone="ok" />
          <Stat n={nHidden} label="Hidden" tone="danger" />
          {injectionReports.length > 0 && <Stat n={injectionReports.length} label="Injection" tone="danger" />}
          {failedCount > 0 && <Stat n={failedCount} label="Failed" tone="danger" />}
        </div>
      )}

      {nav === "overview" && okReports.length > 0 && <OverviewCharts reports={okReports} graph={graph} />}

        {/* Provenance — makes a saved/restored analysis self-describing and auditable. */}
        {nav === "overview" && runMeta && (
          <Section title="🧾 Run Provenance">
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
          </Section>
        )}

        {/* Guardrails — LLM security. Shows prompt-injection scan results per report. */}
        {nav === "overview" && reports.length > 0 && (
          <Section title="🛡️ Guardrails — LLM Security">
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
          </Section>
        )}

        {/* Prioritized fixes, grouped by report name; correlated fixes last */}
        {nav === "overview" && okReports.length > 0 && (
          <Section title="🎯 Prioritized Fixes">
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
          </Section>
        )}

        {/* Cross-tool correlation — only shown once a real correlate result (or failure) exists */}
        {nav === "findings" && (correlation || correlationError) && (
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

        {/* Attack-surface graph + what-if simulation — the core reasoning engine */}
        {nav === "paths" && graphError && (
          <div className="panel">
            <div className="panel-head">🕸️ Attack Surface</div>
            <div className="fail-box" style={{ margin: 14 }}>⚠ Graph build failed: {graphError}. Re-run to retry.</div>
          </div>
        )}
        {nav === "paths" && graph && graph.nodes && graph.nodes.length > 1 && (
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
        {nav === "findings" && reports.length > 0 && (
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

        {nav === "paths" && !graphError && !(graph && graph.nodes && graph.nodes.length > 1) && (
          <div className="empty">No attack paths to show yet.{reports.length > 0 ? " Add a topology (or click “Suggest from reports”) to connect assets into paths." : ""} <button className="linklike" onClick={() => setNav("scan")}>Go to Scan →</button></div>
        )}

        {nav === "findings" && reports.length === 0 && (
          <div className="empty">No findings yet. <button className="linklike" onClick={() => setNav("scan")}>Start a scan →</button></div>
        )}

        {nav === "mitre" && (
          reports.length === 0 ? (
            <div className="empty">No findings to map yet. <button className="linklike" onClick={() => setNav("scan")}>Start a scan →</button></div>
          ) : (() => {
            const tactics = mitreMap(reports.flatMap((r) => r.findings || []));
            const present = TACTIC_ORDER.filter((t) => tactics[t]);
            return (
              <div className="panel">
                <div className="panel-head">🎯 MITRE ATT&CK Coverage <span className="badge">{present.filter((t) => t !== "Unmapped").length} tactic(s)</span></div>
                <div className="ev-note" style={{ margin: "12px 16px" }}>
                  Findings mapped to ATT&CK techniques by a deterministic rule set — an indicative mapping to aid triage, not an authoritative classification.
                </div>
                <div className="mitre-grid">
                  {present.map((t) => (
                    <div key={t} className={`mitre-col ${t === "Unmapped" ? "unmapped" : ""}`}>
                      <div className="mitre-tac">{t}</div>
                      {Object.values(tactics[t]).map((tech, i) => (
                        <div key={i} className="mitre-tech">
                          <div className="mitre-id">{tech.id}{tech.id !== "—" ? " · " : ""}{tech.name}</div>
                          {tech.items.map((f, j) => (
                            <div key={j} className="mitre-item">
                              <span className={`sev sev-${(f.severity || "unknown").toLowerCase()}`}>{f.severity || "?"}</span>
                              {f.name} <span className="fhost">{f.host}</span>
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            );
          })()
        )}

        {nav === "summary" && (
          reports.length === 0 ? (
            <div className="empty">Run a scan first, then generate an executive summary. <button className="linklike" onClick={() => setNav("scan")}>Start a scan →</button></div>
          ) : (
            <div className="panel">
              <div className="panel-head hist-head">
                <span>📝 Executive Summary</span>
                <button className="export-btn" onClick={generateSummary} disabled={execLoading}>
                  {execLoading ? "Generating…" : execSummary ? "Regenerate" : "Generate"}
                </button>
              </div>
              {!execSummary && !execLoading && (
                <div className="empty" style={{ padding: "24px 16px" }}>
                  Click <b>Generate</b> for a plain-English summary of risk posture and top actions — it's also embedded in the PDF export.
                </div>
              )}
              {execLoading && <div className="muted" style={{ padding: "20px 16px" }}>Writing summary… (LLM)</div>}
              {execSummary && !execLoading && <div className="exec-summary">{execSummary}</div>}
            </div>
          )
        )}

        {nav === "compare" && (
          runs.length < 2 ? (
            <div className="empty">Need at least two saved analyses to compare — run a few scans, then come back.</div>
          ) : (
            <div className="panel">
              <div className="panel-head">🔀 Compare two analyses (what changed over time)</div>
              <div className="cmp-pick">
                <div className="cmp-sel">
                  <label>Baseline (before)</label>
                  <select value={cmpA} onChange={(e) => { setCmpA(e.target.value); runCompare(e.target.value, cmpB); }}>
                    <option value="">Select…</option>
                    {runs.map((r) => <option key={r.id} value={r.id}>{(r.label || (r.names || []).join(", ") || r.id).slice(0, 40)} · {r.findings}f</option>)}
                  </select>
                </div>
                <span className="cmp-arrow">→</span>
                <div className="cmp-sel">
                  <label>Compare to (after)</label>
                  <select value={cmpB} onChange={(e) => { setCmpB(e.target.value); runCompare(cmpA, e.target.value); }}>
                    <option value="">Select…</option>
                    {runs.map((r) => <option key={r.id} value={r.id}>{(r.label || (r.names || []).join(", ") || r.id).slice(0, 40)} · {r.findings}f</option>)}
                  </select>
                </div>
              </div>
              {cmpResult?.error && <div className="fail-box" style={{ margin: "0 16px 16px" }}>{cmpResult.error}</div>}
              {cmpResult && !cmpResult.error && (
                <div className="cmp-body">
                  <div className="cmp-summary">
                    <span className="grs bad">＋ {cmpResult.added.length} new</span>
                    <span className="grs ok">✓ {cmpResult.fixed.length} fixed</span>
                    <span className="grs na">= {cmpResult.common.length} unchanged</span>
                  </div>
                  <div className="cmp-cols">
                    <div className="cmp-col">
                      <h4>＋ New findings</h4>
                      {cmpResult.added.length === 0 ? <p className="muted">None</p> : cmpResult.added.map((f, i) => (
                        <div key={i} className="cmp-item"><span className={`sev sev-${(f.severity || "unknown").toLowerCase()}`}>{f.severity || "?"}</span> {f.name} <span className="fhost">{f.host}</span></div>
                      ))}
                    </div>
                    <div className="cmp-col">
                      <h4>✓ Fixed / resolved</h4>
                      {cmpResult.fixed.length === 0 ? <p className="muted">None</p> : cmpResult.fixed.map((f, i) => (
                        <div key={i} className="cmp-item"><span className={`sev sev-${(f.severity || "unknown").toLowerCase()}`}>{f.severity || "?"}</span> {f.name} <span className="fhost">{f.host}</span></div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )
        )}

        {nav === "history" && (
          runs.length === 0 ? (
            <div className="empty">No saved analyses yet — every scan you run is saved here.</div>
          ) : (
            <div className="panel">
              <div className="panel-head hist-head">
                <span>🕘 Saved Analyses</span>
                {runs.some((r) => r.tag) && (
                  <button className="hist-filter" onClick={() => setHideTagged((v) => !v)}>{hideTagged ? "show all" : "hide test/demo"}</button>
                )}
              </div>
              <div className="run-list wide">
                {(hideTagged ? runs.filter((r) => !r.tag) : runs).map((r) => (
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
            </div>
          )
        )}
        </div>
      </main>
    </div>
  );
}

const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info", "Unknown"];
const SEV_COLOR = { Critical: "#ef4444", High: "#f87171", Medium: "#eab308", Low: "#3b82f6", Info: "#38bdf8", Unknown: "#8592a3" };

function Bars({ rows, colorFor }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <div className="bars">
      {rows.map((r, i) => (
        <div key={i} className="bar-row">
          <span className="bar-label" title={r.label}>{r.label}</span>
          <div className="bar-track"><div className="bar-fill" style={{ width: (r.value / max) * 100 + "%", background: colorFor(r) }} /></div>
          <span className="bar-val">{r.value}</span>
        </div>
      ))}
    </div>
  );
}

function Section({ title, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="panel">
      <div className="panel-head hist-head">
        <span>{title}</span>
        <button className="mini-btn" onClick={() => setOpen((o) => !o)} title={open ? "Minimize" : "Expand"}>{open ? "–" : "+"}</button>
      </div>
      {open && children}
    </div>
  );
}

function Donut({ data }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  const R = 42, C = 2 * Math.PI * R;
  let off = 0;
  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 110 110" className="donut-svg">
        <circle cx="55" cy="55" r={R} fill="none" stroke="var(--border)" strokeWidth="13" />
        {data.filter((d) => d.value > 0).map((d, i) => {
          const len = (d.value / total) * C;
          const seg = (
            <circle key={i} cx="55" cy="55" r={R} fill="none" stroke={d.color} strokeWidth="13"
              strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-off} transform="rotate(-90 55 55)" />
          );
          off += len; return seg;
        })}
        <text x="55" y="52" textAnchor="middle" className="donut-num">{total}</text>
        <text x="55" y="67" textAnchor="middle" className="donut-lbl">findings</text>
      </svg>
      <div className="donut-legend">
        {data.filter((d) => d.value > 0).map((d, i) => (
          <div key={i} className="dleg"><span className="ddot" style={{ background: d.color }} />{d.label}<b>{d.value}</b></div>
        ))}
      </div>
    </div>
  );
}

function RiskGauge({ score }) {
  const pct = Math.max(0, Math.min(100, Math.round(score)));
  const band = pct >= 75 ? "Critical" : pct >= 50 ? "High" : pct >= 25 ? "Medium" : "Low";
  const color = pct >= 75 ? "#dc2626" : pct >= 50 ? "#ea580c" : pct >= 25 ? "#b45309" : "#16a34a";
  const cx = 80, cy = 78, R = 60;
  const d = `M ${cx - R} ${cy} A ${R} ${R} 0 0 1 ${cx + R} ${cy}`;
  return (
    <svg viewBox="0 0 160 92" className="gauge-svg">
      <path d={d} fill="none" stroke="var(--border)" strokeWidth="13" strokeLinecap="round" pathLength="100" />
      <path d={d} fill="none" stroke={color} strokeWidth="13" strokeLinecap="round" pathLength="100" strokeDasharray={`${pct} 100`} />
      <text x={cx} y={cy - 12} textAnchor="middle" style={{ fontSize: 30, fontWeight: 800, fill: color, fontFamily: "ui-monospace, monospace" }}>{pct}</text>
      <text x={cx} y={cy + 4} textAnchor="middle" style={{ fontSize: 10.5, fill: "var(--muted)", letterSpacing: "1px" }}>{band.toUpperCase()} RISK</text>
    </svg>
  );
}

function OverviewCharts({ reports, graph }) {
  const [open, setOpen] = useState(true);
  const findings = reports.flatMap((r) => r.findings || []);
  const sev = Object.fromEntries(SEV_ORDER.map((s) => [s, 0]));
  findings.forEach((f) => { const s = SEV_ORDER.includes(f.severity) ? f.severity : "Unknown"; sev[s]++; });
  const repRows = reports.map((r) => ({ label: r.name, value: (r.findings || []).length }));
  const paths = graph?.paths || [];
  const topPri = paths.length ? paths[0].priority : 0;
  const donutData = SEV_ORDER.filter((s) => sev[s] > 0).map((s) => ({ label: s, value: sev[s], color: SEV_COLOR[s] }));
  const score = Math.min(100, sev.Critical * 20 + sev.High * 12 + sev.Medium * 6 + sev.Low * 2 + paths.length * 10);

  return (
    <div className="panel">
      <div className="panel-head hist-head">
        <span>📊 Dashboard</span>
        <button className="linklike" onClick={() => setOpen((o) => !o)}>{open ? "Hide ▲" : "Show ▼"}</button>
      </div>
      {open && (
      <div className="dash">
        <div className="dash-card center">
          <div className="dash-title">Overall risk</div>
          <RiskGauge score={score} />
        </div>
        <div className="dash-card">
          <div className="dash-title">Findings by severity</div>
          {donutData.length ? <Donut data={donutData} /> : <p className="muted">No findings.</p>}
        </div>
        <div className="dash-card">
          <div className="dash-title">Findings by report</div>
          <Bars rows={repRows} colorFor={() => "var(--mint)"} />
        </div>
        <div className="dash-card metrics">
          <div className="dash-title">Attack surface</div>
          <div className="metric"><span>{paths.length}</span> attack path(s)</div>
          <div className="metric"><span>{(graph?.reachable_critical || []).length}</span> reachable critical asset(s)</div>
          <div className="metric"><span>{topPri}</span> top path priority</div>
        </div>
      </div>
      )}
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
              <><b>Topology-backed</b> = supplied-topology edges + an exploitable finding at every hop. This is <b>not</b> lab-validated exploitability (config, prerequisites and chaining are unverified). Others remain hypothetical.</>
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
                ? "TOPOLOGY-BACKED · vuln-supported"
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
