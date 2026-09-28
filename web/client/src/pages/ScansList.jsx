import { useEffect, useState, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../lib/api.js';
import { fmtDate, fmtDuration } from '../lib/format.js';
import { StatusBadge } from '../components/Badges.jsx';

export default function ScansList() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
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
  };

  useEffect(() => {
    load();
    timerRef.current = setInterval(() => {
      setScans((cur) => {
        if (cur.some((s) => s.status === 'running')) load();
        return cur;
      });
    }, 5000);
    return () => clearInterval(timerRef.current);
  }, []);

  const onDelete = async (runId, e) => {
    e.stopPropagation();
    if (!confirm(`Delete scan ${runId}? This cannot be undone.`)) return;
    try {
      await api.deleteScan(runId);
      setScans((cur) => cur.filter((s) => s.run_id !== runId));
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  };

  const q = query.toLowerCase();
  const filtered = scans.filter(
    (s) =>
      s.run_id.includes(q) ||
      (s.status || '').includes(q) ||
      (s.params?.repo_path || '').toLowerCase().includes(q)
  );

  return (
    <>
      <div className="page-header">
        <h1>Scan History</h1>
        <Link to="/scan/new" className="btn btn-primary">+ New Scan</Link>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="search-bar">
            <input
              type="text"
              className="form-control"
              placeholder="🔍 Filter by run ID or status…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
        </div>
        <div className="card-body p-0">
          {loading ? (
            <div className="loading-msg">Loading scan history…</div>
          ) : !filtered.length ? (
            <div className="empty-msg">
              No scans found. <Link to="/scan/new">Start your first scan →</Link>
            </div>
          ) : (
            <table className="table table-hover">
              <thead>
                <tr>
                  <th>Run ID</th><th>Status</th><th>Findings</th><th>Repository</th>
                  <th>Started</th><th>Duration</th><th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((s) => {
                  const repo = s.params?.repo_path || '';
                  const repoShort = repo.split(/[\\/]/).pop() || repo || '—';
                  return (
                    <tr
                      key={s.run_id}
                      onClick={() => navigate(`/scans/${s.run_id}`)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td><code>{s.run_id}</code></td>
                      <td><StatusBadge status={s.status} /></td>
                      <td>{s.finding_count ?? '—'}</td>
                      <td title={repo}>{repoShort}</td>
                      <td>{fmtDate(s.started_at)}</td>
                      <td>{fmtDuration(s.started_at, s.finished_at)}</td>
                      <td onClick={(e) => e.stopPropagation()} style={{ whiteSpace: 'nowrap' }}>
                        {s.status === 'running' ? (
                          <Link to={`/scan/${s.run_id}/live`} className="btn btn-sm btn-primary">Live</Link>
                        ) : (
                          <Link to={`/scans/${s.run_id}`} className="btn btn-sm btn-secondary">Results</Link>
                        )}{' '}
                        <button className="btn btn-sm btn-danger" onClick={(e) => onDelete(s.run_id, e)}>🗑</button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
