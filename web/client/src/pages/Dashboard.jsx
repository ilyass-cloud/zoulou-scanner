import { useEffect, useState, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../lib/api.js';
import { fmtDate, fmtDuration } from '../lib/format.js';
import { StatusBadge } from '../components/Badges.jsx';
import BarChart from '../components/BarChart.jsx';

const SEV_LABELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_COLORS = ['#7c3aed', '#ef4444', '#f59e0b', '#3b82f6', '#9ca3af'];

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [sevValues, setSevValues] = useState(null);
  const navigate = useNavigate();
  const timerRef = useRef(null);

  const load = async () => {
    let data = [];
    try {
      data = await api.listScans();
    } catch {
      data = [];
    }
    setScans(data);
    setLoading(false);

    const latestDone = data.find((s) => s.status === 'done');
    if (latestDone) {
      try {
        const report = await api.getReport(latestDone.run_id);
        const bySev = report.summary?.by_severity || {};
        const values = SEV_LABELS.map((l) => bySev[l] || 0);
        setSevValues(values.some((v) => v > 0) ? values : null);
      } catch {
        /* ignore */
      }
    }
  };

  useEffect(() => {
    load();
    // Auto-refresh while any scan is running.
    timerRef.current = setInterval(() => {
      setScans((cur) => {
        if (cur.some((s) => s.status === 'running')) load();
        return cur;
      });
    }, 5000);
    return () => clearInterval(timerRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const running = scans.filter((s) => s.status === 'running').length;
  const totalFindings = scans.reduce((a, s) => a + (s.finding_count || 0), 0);
  const last = scans[0];
  const recent = scans.slice(0, 8);

  return (
    <>
      <div className="page-header">
        <h1>Dashboard</h1>
        <Link to="/scan/new" className="btn btn-primary">+ New Scan</Link>
      </div>

      <div className="stats-grid">
        <Stat value={scans.length} label="Total Scans" />
        <Stat value={running} label="Running" />
        <Stat value={totalFindings} label="Total Findings" />
        <Stat value={last ? fmtDate(last.started_at).split(',')[0] : '—'} label="Last Scan" />
      </div>

      {sevValues && (
        <div className="card">
          <div className="card-header"><h2>Risk Distribution (latest scan)</h2></div>
          <div className="card-body">
            <div className="chart-container">
              <BarChart labels={SEV_LABELS} values={sevValues} colors={SEV_COLORS}
                title="Findings by severity" />
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h2>Recent Scans</h2>
          <Link to="/scans" className="btn btn-sm">View all</Link>
        </div>
        <div className="card-body">
          {loading ? (
            <div className="loading-msg">Loading…</div>
          ) : recent.length === 0 ? (
            <div className="empty-msg">
              No scans yet. <Link to="/scan/new">Start your first scan →</Link>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Run ID</th><th>Status</th><th>Findings</th>
                  <th>Started</th><th>Duration</th><th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((s) => (
                  <tr
                    key={s.run_id}
                    onClick={() => navigate(`/scans/${s.run_id}`)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td><code>{s.run_id}</code></td>
                    <td><StatusBadge status={s.status} /></td>
                    <td>{s.finding_count ?? '—'}</td>
                    <td>{fmtDate(s.started_at)}</td>
                    <td>{fmtDuration(s.started_at, s.finished_at)}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <Link to={`/scans/${s.run_id}`} className="btn btn-sm btn-secondary">Results</Link>{' '}
                      {s.status === 'running' && (
                        <Link to={`/scan/${s.run_id}/live`} className="btn btn-sm btn-primary">Live</Link>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {scans.length > 0 && (
        <div className="card">
          <div className="card-header"><h2>Scan Timeline</h2></div>
          <div className="card-body">
            <div className="timeline">
              {scans.slice(0, 10).map((s) => (
                <div key={s.run_id} className="timeline-item">
                  <div
                    className="timeline-dot"
                    style={{
                      background:
                        s.status === 'done' ? '#22c55e' : s.status === 'error' ? '#ef4444' : '#3b82f6',
                    }}
                  />
                  <div>
                    <div style={{ fontSize: '.85rem', fontWeight: 600 }}>
                      <Link to={`/scans/${s.run_id}`}>{s.run_id}</Link> <StatusBadge status={s.status} />
                    </div>
                    <div style={{ fontSize: '.75rem', color: 'var(--text-muted)' }}>{fmtDate(s.started_at)}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function Stat({ value, label }) {
  return (
    <div className="stat-card">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
