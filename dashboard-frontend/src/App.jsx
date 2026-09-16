import { useState, useEffect, useCallback } from "react";

const API_BASE = "http://localhost:8000/api";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_COLORS = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  info: "#6b7280",
};
const STATUS_LABELS = {
  new: "New",
  investigating: "Investigating",
  resolved: "Resolved",
  dismissed: "Dismissed",
};
const STATUS_ICONS = { new: "🔴", investigating: "🔍", resolved: "✅", dismissed: "⏏️" };

function useIncidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/incidents`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setIncidents(await res.json());
    } catch (e) {
      setError(e.message);
      setIncidents(getMockData());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);
  return { incidents, loading, error, refresh: fetchIncidents, setIncidents };
}

function getMockData() {
  return [
    { id: "INC-001", title: "Database connection pool exhausted", severity: "critical", status: "new", source: "db-monitor", alert_count: 12, created_at: "2025-01-15T08:23:11Z", updated_at: "2025-01-15T08:30:00Z", assignee: null, description: "Primary DB connection pool at 100% capacity. All new queries are being rejected." },
    { id: "INC-002", title: "API latency exceeding 5s threshold", severity: "high", status: "investigating", source: "api-gateway", alert_count: 8, created_at: "2025-01-15T07:45:00Z", updated_at: "2025-01-15T08:15:00Z", assignee: "oncall-backend", description: "P99 latency for /api/v2/orders has exceeded 5000ms for the past 30 minutes." },
    { id: "INC-003", title: "Disk usage above 85% on worker-03", severity: "medium", status: "new", source: "infra-monitor", alert_count: 3, created_at: "2025-01-15T06:00:00Z", updated_at: "2025-01-15T06:00:00Z", assignee: null, description: "Worker node worker-03 disk utilization at 87%. Projected to reach 95% in 4 hours." },
    { id: "INC-004", title: "SSL certificate expiring in 7 days", severity: "low", status: "new", source: "cert-checker", alert_count: 1, created_at: "2025-01-14T12:00:00Z", updated_at: "2025-01-14T12:00:00Z", assignee: null, description: "Certificate for api.example.com expires on 2025-01-22." },
    { id: "INC-005", title: "Stale cache entries detected", severity: "info", status: "dismissed", source: "cache-manager", alert_count: 2, created_at: "2025-01-13T09:00:00Z", updated_at: "2025-01-13T10:00:00Z", assignee: "system", description: "Cache invalidation lag detected. Entries older than TTL found in regional caches." },
    { id: "INC-006", title: "Payment gateway timeout rate elevated", severity: "high", status: "investigating", source: "payment-svc", alert_count: 6, created_at: "2025-01-15T08:10:00Z", updated_at: "2025-01-15T08:25:00Z", assignee: "oncall-payments", description: "Timeout rate for Stripe integration at 4.2%, above 1% threshold." },
    { id: "INC-007", title: "Memory leak in auth service", severity: "critical", status: "investigating", source: "auth-svc", alert_count: 5, created_at: "2025-01-15T07:00:00Z", updated_at: "2025-01-15T08:20:00Z", assignee: "oncall-backend", description: "Auth service RSS growing ~50MB/hour. Restart temporarily clears." },
  ];
}

export default function App() {
  const { incidents, loading, error, refresh, setIncidents } = useIncidents();
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selected, setSelected] = useState(null);
  const [updating, setUpdating] = useState(false);

  const filtered = incidents
    .filter((i) => severityFilter === "all" || i.severity === severityFilter)
    .filter((i) => statusFilter === "all" || i.status === statusFilter)
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const handleStatusChange = async (id, newStatus) => {
    setUpdating(true);
    try {
      const res = await fetch(`${API_BASE}/incidents/${id}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        setIncidents((prev) => prev.map((i) => (i.id === id ? { ...i, status: newStatus, updated_at: new Date().toISOString() } : i)));
      } else throw new Error("patch failed");
    } catch {
      setIncidents((prev) => prev.map((i) => (i.id === id ? { ...i, status: newStatus, updated_at: new Date().toISOString() } : i)));
    }
    setUpdating(false);
  };

  const fmtTime = (iso) => new Date(iso).toLocaleString();

  return (
    <div className="app">
      <header className="header">
        <h1>🚨 Incident Triage Dashboard</h1>
        <button className="btn-refresh" onClick={refresh} disabled={loading}>{loading ? "Loading…" : "↻ Refresh"}</button>
      </header>

      <div className="filters">
        <div className="filter-group">
          <span className="filter-label">Severity:</span>
          {["all", "critical", "high", "medium", "low", "info"].map((s) => (
            <button key={s} className={`filter-btn ${severityFilter === s ? "active" : ""}`} style={s !== "all" && severityFilter === s ? { borderColor: SEVERITY_COLORS[s], color: SEVERITY_COLORS[s] } : {}} onClick={() => setSeverityFilter(s)}>
              {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
        <div className="filter-group">
          <span className="filter-label">Status:</span>
          {["all", "new", "investigating", "resolved", "dismissed"].map((s) => (
            <button key={s} className={`filter-btn ${statusFilter === s ? "active" : ""}`} onClick={() => setStatusFilter(s)}>
              {s === "all" ? "All" : `${STATUS_ICONS[s]} ${STATUS_LABELS[s]}`}
            </button>
          ))}
        </div>
        <span className="result-count">{filtered.length} incident{filtered.length !== 1 ? "s" : ""}</span>
      </div>

      {error && <div className="banner">⚠️ API unreachable — showing mock data</div>}

      <div className="table-wrap">
        <table className="inc-table">
          <thead>
            <tr>
              <th>Severity</th><th>ID</th><th>Title</th><th>Status</th><th>Alerts</th><th>Assignee</th><th>Updated</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((inc) => (
              <tr key={inc.id} className={`row-${inc.severity} ${selected?.id === inc.id ? "row-selected" : ""}`} onClick={() => setSelected(inc)}>
                <td><span className="sev-badge" style={{ background: SEVERITY_COLORS[inc.severity] }}>{inc.severity.toUpperCase()}</span></td>
                <td className="mono">{inc.id}</td>
                <td className="title-cell">{inc.title}</td>
                <td>{STATUS_ICONS[inc.status]} {STATUS_LABELS[inc.status]}</td>
                <td className="center">{inc.alert_count}</td>
                <td>{inc.assignee || "—"}</td>
                <td className="mono small">{fmtTime(inc.updated_at)}</td>
              </tr>
            ))}
            {filtered.length === 0 && <tr><td colSpan={7} className="empty">No incidents match filters</td></tr>}
          </tbody>
        </table>
      </div>

      {selected && (
        <div className="overlay" onClick={() => setSelected(null)}>
          <div className="detail-panel" onClick={(e) => e.stopPropagation()}>
            <button className="btn-close" onClick={() => setSelected(null)}>✕</button>
            <div className="detail-header">
              <span className="sev-badge lg" style={{ background: SEVERITY_COLORS[selected.severity] }}>{selected.severity.toUpperCase()}</span>
              <h2>{selected.title}</h2>
              <span className="mono">{selected.id}</span>
            </div>
            <div className="detail-meta">
              <div><strong>Source:</strong> {selected.source}</div>
              <div><strong>Alert Count:</strong> {selected.alert_count}</div>
              <div><strong>Assignee:</strong> {selected.assignee || "Unassigned"}</div>
              <div><strong>Created:</strong> {fmtTime(selected.created_at)}</div>
              <div><strong>Updated:</strong> {fmtTime(selected.updated_at)}</div>
            </div>
            <p className="detail-desc">{selected.description}</p>
            <div className="detail-actions">
              <strong>Triage:</strong>
              {Object.entries(STATUS_LABELS).map(([key, label]) => (
                <button key={key} className={`action-btn ${selected.status === key ? "current" : ""}`} disabled={updating || selected.status === key} onClick={() => handleStatusChange(selected.id, key)}>
                  {STATUS_ICONS[key]} {label}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}