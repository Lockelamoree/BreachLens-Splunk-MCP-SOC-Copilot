import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  CheckCircle2,
  Clock,
  Download,
  FileText,
  Network,
  Play,
  Radio,
  RefreshCw,
  Search,
  ShieldCheck,
  Terminal,
  X
} from "lucide-react";

type AlertItem = {
  alert_id: string;
  title: string;
  severity: string;
  severity_score: number;
  status: string;
  time: string;
  user: string;
  src_ip: string;
  host: string;
  asset: string;
  description: string;
  recommended_objective: string;
};

type Evidence = {
  id: string;
  query_id: string;
  time: string;
  source: string;
  title: string;
  summary: string;
  fields: Record<string, string | number | boolean | null>;
};

type TimelineEvent = {
  time: string;
  phase: string;
  title: string;
  narrative: string;
  evidence_ids: string[];
};

type MitreMapping = {
  technique_id: string;
  technique: string;
  tactic: string;
  rationale: string;
  evidence_ids: string[];
};

type ResponseAction = {
  priority: string;
  owner: string;
  action: string;
  evidence_ids: string[];
};

type QueryTranscript = {
  query_id: string;
  purpose: string;
  spl: string;
  result_count: number;
  tool: string;
};

type AnalystNote = {
  provider: string;
  status: string;
  narrative: string;
  evidence_ids: string[];
};

type Investigation = {
  investigation_id: string;
  alert: AlertItem;
  status: string;
  summary: string;
  confidence: string;
  objective: string;
  evidence: Evidence[];
  timeline: TimelineEvent[];
  mitre: MitreMapping[];
  response_actions: ResponseAction[];
  spl_transcript: QueryTranscript[];
  analyst_note: AnalystNote | null;
  warnings: string[];
};

type DetectionDraft = {
  detection_id: string;
  title: string;
  severity: string;
  spl: string;
  sigma: string;
  evidence_ids: string[];
};

type Health = {
  status: string;
  mode: string;
  splunk_client: string;
  splunk_index?: string;
  ai_provider?: string;
  ai_model?: string;
  ai_model_url?: string;
  investigations_in_memory?: number;
};

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

const fallbackAlerts: AlertItem[] = [
  {
    alert_id: "BLS-2026-001",
    title: "Impossible travel followed by suspicious cloud API activity",
    severity: "critical",
    severity_score: 96,
    status: "sample",
    time: "2026-05-28T09:24:18Z",
    user: "maria.chen",
    src_ip: "203.0.113.45",
    host: "LAPTOP-MCHEN",
    asset: "okta/aws",
    description: "Sample alert loaded while the API is unavailable.",
    recommended_objective: "Start the backend to investigate with Splunk evidence."
  }
];

function App() {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string>("");
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [detections, setDetections] = useState<DetectionDraft[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [activeTab, setActiveTab] = useState<"evidence" | "spl" | "detections">("evidence");
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [detecting, setDetecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedAlert = useMemo(
    () => alerts.find((alert) => alert.alert_id === selectedAlertId) ?? alerts[0],
    [alerts, selectedAlertId]
  );
  const selectedEvidence = useMemo(
    () => investigation?.evidence.find((item) => item.id === selectedEvidenceId) ?? null,
    [investigation, selectedEvidenceId]
  );
  const aiProvider = investigation?.analyst_note?.provider ?? health?.ai_provider ?? "pending";
  const aiModel = health?.ai_model ?? (aiProvider === "deterministic" ? "deterministic_fallback" : "pending");
  const aiModelUrl = health?.ai_model_url ?? "";

  useEffect(() => {
    void fetchHealth();
    void fetchAlerts();
  }, []);

  async function fetchHealth() {
    try {
      const response = await fetch(`${API_BASE}/health`);
      if (response.ok) {
        setHealth((await response.json()) as Health);
      }
    } catch {
      setHealth(null);
    }
  }

  async function fetchAlerts() {
    setError(null);
    void fetchHealth();
    try {
      const response = await fetch(`${API_BASE}/api/alerts`);
      if (!response.ok) {
        throw new Error(`API returned ${response.status}`);
      }
      const payload = (await response.json()) as { alerts: AlertItem[] };
      setAlerts(payload.alerts);
      setSelectedAlertId(payload.alerts[0]?.alert_id ?? "");
    } catch (fetchError) {
      setAlerts(fallbackAlerts);
      setSelectedAlertId(fallbackAlerts[0].alert_id);
      setError(`API unavailable: ${(fetchError as Error).message}`);
    }
  }

  async function startInvestigation() {
    if (!selectedAlert) {
      return;
    }
    setLoading(true);
    setError(null);
    setDetections([]);
    try {
      const response = await fetch(`${API_BASE}/api/investigations`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alert_id: selectedAlert.alert_id,
          objective: selectedAlert.recommended_objective
        })
      });
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(detail || `API returned ${response.status}`);
      }
      const payload = (await response.json()) as Investigation;
      setInvestigation(payload);
      setSelectedEvidenceId(null);
      setActiveTab("evidence");
    } catch (investigationError) {
      setError(`Investigation failed: ${(investigationError as Error).message}`);
    } finally {
      setLoading(false);
    }
  }

  async function generateDetections() {
    if (!investigation) {
      return;
    }
    setDetecting(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/api/detections`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ investigation_id: investigation.investigation_id })
      });
      if (!response.ok) {
        throw new Error(`API returned ${response.status}`);
      }
      const payload = (await response.json()) as { detections: DetectionDraft[] };
      setDetections(payload.detections);
      setActiveTab("detections");
    } catch (detectionError) {
      setError(`Detection generation failed: ${(detectionError as Error).message}`);
    } finally {
      setDetecting(false);
    }
  }

  function downloadDetections() {
    const blob = new Blob([JSON.stringify(detections, null, 2)], {
      type: "application/json"
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${investigation?.investigation_id ?? "breachlens"}-detections.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function downloadLedger() {
    if (!investigation) {
      return;
    }
    const response = await fetch(`${API_BASE}/api/investigations/${investigation.investigation_id}/ledger`);
    if (!response.ok) {
      setError(`Evidence ledger export failed: API returned ${response.status}`);
      return;
    }
    downloadBlob(
      `${investigation.investigation_id}-evidence-ledger.json`,
      JSON.stringify(await response.json(), null, 2),
      "application/json"
    );
  }

  async function downloadReport() {
    if (!investigation) {
      return;
    }
    const response = await fetch(`${API_BASE}/api/investigations/${investigation.investigation_id}/report.md`);
    if (!response.ok) {
      setError(`Incident report export failed: API returned ${response.status}`);
      return;
    }
    downloadBlob(
      `${investigation.investigation_id}-incident-report.md`,
      await response.text(),
      "text/markdown"
    );
  }

  function downloadBlob(filename: string, content: string, type: string) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="Alert queue">
        <div className="brand-row">
          <ShieldCheck aria-hidden="true" />
          <div>
            <h1>BreachLens</h1>
            <span>Splunk MCP SOC Copilot</span>
          </div>
        </div>

        <div className="sidebar-actions">
          <button className="icon-button" title="Refresh alerts" onClick={() => void fetchAlerts()}>
            <RefreshCw aria-hidden="true" />
          </button>
          <span className="queue-count">{alerts.length} alerts</span>
        </div>

        <div className="alert-list">
          {alerts.map((alert) => (
            <button
              key={alert.alert_id}
              className={`alert-card ${alert.alert_id === selectedAlert?.alert_id ? "selected" : ""}`}
              onClick={() => setSelectedAlertId(alert.alert_id)}
            >
              <span className={`severity-dot ${alert.severity.toLowerCase()}`} />
              <span className="alert-title">{alert.title}</span>
              <span className="alert-meta">
                {alert.alert_id} / {alert.user} / {alert.severity_score}
              </span>
            </button>
          ))}
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Security track demo</p>
            <h2>{selectedAlert?.title ?? "No alert selected"}</h2>
            {selectedAlert && (
              <p className="target-line">
                {selectedAlert.user} / {selectedAlert.host} / {selectedAlert.src_ip}
              </p>
            )}
            <div className="source-pills" aria-label="Data source">
              <span>{health?.mode ?? "unknown"}</span>
              <span>{health?.splunk_client ?? "api offline"}</span>
              <span>{aiProvider}</span>
              <span title={health?.ai_model ?? undefined}>{formatModelName(aiModel)}</span>
              {aiModelUrl && (
                <a href={aiModelUrl} target="_blank" rel="noreferrer" title={aiModelUrl}>
                  Hugging Face
                </a>
              )}
            </div>
          </div>
          <div className="topbar-actions">
            <button
              className="primary-action"
              title="Run investigation"
              disabled={!selectedAlert || loading}
              onClick={() => void startInvestigation()}
            >
              <Play aria-hidden="true" />
              {loading ? "Investigating" : "Investigate"}
            </button>
            <button
              className="secondary-action"
              title="Generate detection drafts"
              disabled={!investigation || detecting}
              onClick={() => void generateDetections()}
            >
              <FileText aria-hidden="true" />
              {detecting ? "Generating" : "Detections"}
            </button>
          </div>
        </header>

        {error && (
          <div className="notice" role="status">
            <AlertTriangle aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}

        <section className="summary-grid">
          <Metric label="Confidence" value={investigation?.confidence ?? "pending"} icon={<CheckCircle2 />} />
          <Metric label="Evidence" value={`${investigation?.evidence.length ?? 0}`} icon={<Radio />} />
          <Metric label="Queries" value={`${investigation?.spl_transcript.length ?? 0}`} icon={<Terminal />} />
          <Metric label="AI Model" value={formatModelName(aiModel)} icon={<Activity />} />
        </section>

        {investigation ? (
          <>
          <section className="analyst-note" aria-label="AI analyst note">
            <div className="section-heading">
              <Activity aria-hidden="true" />
              <h3>AI Analyst Note</h3>
            </div>
            <div className="query-topline">
              <strong>{investigation.analyst_note?.provider ?? "none"}</strong>
              <span>{investigation.analyst_note?.status ?? "not generated"}</span>
              {aiModelUrl ? (
                <a href={aiModelUrl} target="_blank" rel="noreferrer" title={aiModelUrl}>
                  {health?.ai_model ?? "model unavailable"}
                </a>
              ) : (
                <small title={health?.ai_model ?? undefined}>{health?.ai_model ?? "model unavailable"}</small>
              )}
            </div>
            <p>{investigation.analyst_note?.narrative ?? "No AI analyst note generated."}</p>
            <EvidenceChips ids={investigation.analyst_note?.evidence_ids ?? []} onSelect={setSelectedEvidenceId} />
          </section>

          <section className="impact-band" aria-label="Impact meter">
            <div className="section-heading">
              <BadgeCheck aria-hidden="true" />
              <h3>Impact Meter</h3>
            </div>
            <div className="impact-grid">
              <Impact label="Triage Compression" value="20m -> <2m" />
              <Impact label="Affected Assets" value="identity, cloud, endpoint, proxy" />
              <Impact label="Evidence Gate" value={`${investigation.evidence.length} verified items`} />
              <Impact label="Package" value="ledger + report ready" />
            </div>
            <div className="package-actions">
              <button className="secondary-action" onClick={() => void downloadLedger()}>
                <Download aria-hidden="true" />
                Ledger
              </button>
              <button className="secondary-action" onClick={() => void downloadReport()}>
                <FileText aria-hidden="true" />
                Report
              </button>
            </div>
          </section>

          <div className="content-grid">
            <section className="main-panel">
              <div className="section-heading">
                <Clock aria-hidden="true" />
                <h3>Incident Timeline</h3>
              </div>
              <div className="timeline">
                {investigation.timeline.map((event) => (
                  <article className="timeline-item" key={`${event.time}-${event.title}`}>
                    <span className="timeline-time">{formatTime(event.time)}</span>
                    <div>
                      <span className="phase">{event.phase}</span>
                      <h4>{event.title}</h4>
                      <p>{event.narrative}</p>
                      <EvidenceChips ids={event.evidence_ids} onSelect={setSelectedEvidenceId} />
                    </div>
                  </article>
                ))}
              </div>
            </section>

            <aside className="right-panel">
              <section>
                <div className="section-heading">
                  <Network aria-hidden="true" />
                  <h3>ATT&CK</h3>
                </div>
                <div className="mitre-list">
                  {investigation.mitre.map((mapping) => (
                    <article className="mitre-row" key={mapping.technique_id}>
                      <strong>{mapping.technique_id}</strong>
                      <span>{mapping.technique}</span>
                      <small>{mapping.tactic}</small>
                    </article>
                  ))}
                </div>
              </section>

              <section>
                <div className="section-heading">
                  <ShieldCheck aria-hidden="true" />
                  <h3>Response</h3>
                </div>
                <div className="action-list">
                  {investigation.response_actions.map((action) => (
                    <article className="action-row" key={`${action.owner}-${action.action}`}>
                      <span className="priority">{action.priority}</span>
                      <div>
                        <strong>{action.owner}</strong>
                        <p>{action.action}</p>
                      </div>
                    </article>
                  ))}
                </div>
              </section>
            </aside>
          </div>
          </>
        ) : (
          <div className="empty-state">
            <AlertTriangle aria-hidden="true" />
            <h3>Awaiting investigation</h3>
            <p>Select an alert and run the MCP-backed investigation.</p>
          </div>
        )}

        {investigation && (
          <section className="tab-panel">
            <div className="tabs" role="tablist" aria-label="Investigation artifacts">
              <button className={activeTab === "evidence" ? "active" : ""} onClick={() => setActiveTab("evidence")}>
                Evidence
              </button>
              <button className={activeTab === "spl" ? "active" : ""} onClick={() => setActiveTab("spl")}>
                SPL
              </button>
              <button className={activeTab === "detections" ? "active" : ""} onClick={() => setActiveTab("detections")}>
                Detections
              </button>
            </div>

            {activeTab === "evidence" && (
              <div className="evidence-grid">
                {investigation.evidence.map((item) => (
                  <article className="evidence-card" key={item.id}>
                    <div className="evidence-topline">
                      <span>{item.id}</span>
                      <small>{item.source}</small>
                    </div>
                    <h4>{item.title}</h4>
                    <p>{item.summary}</p>
                    <button className="text-action" onClick={() => setSelectedEvidenceId(item.id)}>
                      <Search aria-hidden="true" />
                      Inspect
                    </button>
                  </article>
                ))}
              </div>
            )}

            {activeTab === "spl" && (
              <div className="query-list">
                {investigation.spl_transcript.map((query) => (
                  <article className="query-card" key={query.query_id}>
                    <div className="query-topline">
                      <strong>{query.query_id}</strong>
                      <span>{query.tool}</span>
                      <small>{query.result_count} rows</small>
                    </div>
                    <p>{query.purpose}</p>
                    <pre>{query.spl}</pre>
                  </article>
                ))}
              </div>
            )}

            {activeTab === "detections" && (
              <div className="detection-panel">
                <div className="detection-actions">
                  <button className="secondary-action" onClick={() => void generateDetections()} disabled={detecting}>
                    <FileText aria-hidden="true" />
                    {detecting ? "Generating" : "Generate"}
                  </button>
                  <button className="icon-button" title="Download detections" onClick={downloadDetections} disabled={!detections.length}>
                    <Download aria-hidden="true" />
                  </button>
                </div>
                {detections.map((draft) => (
                  <article className="detection-card" key={draft.detection_id}>
                    <div className="query-topline">
                      <strong>{draft.title}</strong>
                      <span>{draft.severity}</span>
                    </div>
                    <EvidenceChips ids={draft.evidence_ids} onSelect={setSelectedEvidenceId} />
                    <pre>{draft.spl}</pre>
                  </article>
                ))}
              </div>
            )}
          </section>
        )}

        {selectedEvidence && (
          <aside className="evidence-drawer" aria-label="Evidence details">
            <div className="drawer-header">
              <div>
                <span className="phase">{selectedEvidence.id}</span>
                <h3>{selectedEvidence.title}</h3>
                <p>{selectedEvidence.source} / {selectedEvidence.query_id}</p>
              </div>
              <button className="icon-button" title="Close evidence details" onClick={() => setSelectedEvidenceId(null)}>
                <X aria-hidden="true" />
              </button>
            </div>
            <p>{selectedEvidence.summary}</p>
            <pre>{JSON.stringify(selectedEvidence.fields, null, 2)}</pre>
          </aside>
        )}
      </section>
    </main>
  );
}

function Metric({ label, value, icon }: { label: string; value: string; icon: JSX.Element }) {
  return (
    <article className="metric">
      <span className="metric-icon">{icon}</span>
      <div>
        <small>{label}</small>
        <strong>{value}</strong>
      </div>
    </article>
  );
}

function Impact({ label, value }: { label: string; value: string }) {
  return (
    <article className="impact-item">
      <small>{label}</small>
      <strong>{value}</strong>
    </article>
  );
}

function EvidenceChips({ ids, onSelect }: { ids: string[]; onSelect?: (id: string) => void }) {
  return (
    <div className="evidence-chips">
      {ids.map((id) => (
        <button key={id} onClick={() => onSelect?.(id)}>{id}</button>
      ))}
    </div>
  );
}

function formatTime(value: string) {
  if (!value) {
    return "unknown";
  }
  return value.replace("T", " ").replace("Z", " UTC");
}

function formatModelName(value: string) {
  if (value === "hf.co/LockeLamora2077/NiNa:latest") {
    return "NiNa:latest";
  }
  if (value === "hf.co/LockeLamora2077/NiNa_final:latest") {
    return "NiNa_final:latest";
  }
  return value;
}

export default App;


