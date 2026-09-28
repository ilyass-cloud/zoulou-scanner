import { memo, useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api } from '../lib/api.js';
import { fmtDate, fmtLocation, SEV_ORDER } from '../lib/format.js';
import { SeverityBadge, ScoreBar } from '../components/Badges.jsx';
import BarChart from '../components/BarChart.jsx';
import FindingModal from '../components/FindingModal.jsx';

const SEV_LABELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_COLORS = ['#7c3aed', '#ef4444', '#f59e0b', '#3b82f6', '#9ca3af'];
const SRC_COLORS = ['#3b82f6', '#22c55e', '#f59e0b', '#8b5cf6', '#ef4444'];

// Typing re-runs the filter over every finding and re-renders the table, so the
// query is debounced; the input itself stays fully responsive.
const SEARCH_DEBOUNCE_MS = 200;

// Hoisted: an object literal in JSX is a new object on every render, which
// defeats memoisation on the row below and churns style props for nothing.
const ROW_STYLE = { cursor: 'pointer' };
const LOCATION_STYLE = { fontSize: '.75rem' };
const IDS_STYLE = { fontSize: '.78rem' };
const TOOL_STYLE = { fontSize: '.78rem', color: 'var(--text-muted)' };
const RELATED_STYLE = { color: 'var(--accent)', fontSize: '.75rem', marginLeft: '.3rem' };

// A `th` with an onClick handler is invisible to the keyboard and announces no
// sort state. The control is a real button, and `aria-sort` on the header tells
// assistive technology which column orders the table and in which direction.
function SortHeader({ col, label, sortCol, sortDir, onSort, sortClass }) {
  const active = sortCol === col;
  const ariaSort = active ? (sortDir === -1 ? 'descending' : 'ascending') : 'none';
  return (
    <th scope="col" className={sortClass(col)} aria-sort={ariaSort}>
      <button type="button" className="th-sort-btn" onClick={() => onSort(col)}>
        {label}
        <span aria-hidden="true"> ↕</span>
        <span className="visually-hidden">
          {active
            ? `, sorted ${ariaSort}. Activate to reverse the order.`
            : ', not sorted. Activate to sort by this column.'}
        </span>
      </button>
    </th>
  );
}

// Memoised so opening the finding modal — or any other state change on the
// page — re-renders only the rows whose data actually changed. Previously a
// single click re-rendered every row in the table.
const FindingRow = memo(function FindingRow({ finding, onSelect }) {
  const ids = [...(finding.cve || []), ...(finding.cwe || [])].slice(0, 3).join(', ') || '—';
  const relatedCount = (finding.related_ids || []).length;

  // The row was click-only, so its details were unreachable without a mouse
  // (WCAG 2.1.1). It is now focusable and activated by Enter or Space, and
  // named so the row's purpose is announced rather than read as bare cells.
  const activate = () => onSelect(finding);
  const onKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      activate();
    }
  };

  return (
    <tr
      data-id={finding.id}
      onClick={activate}
      onKeyDown={onKeyDown}
      tabIndex={0}
      role="button"
      aria-label={`View details for ${finding.title}, severity ${finding.severity_raw}`}
      style={ROW_STYLE}
    >
      <td><ScoreBar score={finding.risk_score} /></td>
      <td><SeverityBadge severity={finding.severity_raw} /></td>
      <td><span className="badge badge-neutral">{finding.source}</span></td>
      <td>
        {finding.title}
        {relatedCount > 0 && (
          <span style={RELATED_STYLE}>
            <span aria-hidden="true">🔗{relatedCount}</span>
            <span className="visually-hidden">{relatedCount} related findings</span>
          </span>
        )}
      </td>
      <td><code style={LOCATION_STYLE}>{fmtLocation(finding.location)}</code></td>
      <td style={IDS_STYLE}>{ids}</td>
      <td style={TOOL_STYLE}>{finding.tool}</td>
    </tr>
  );
});

export default function ScanDetail() {
  const { runId } = useParams();
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [modalFinding, setModalFinding] = useState(null);

  // Filters + sort. `search` drives the input; `query` drives the filter, and
  // trails it by SEARCH_DEBOUNCE_MS so a keystroke does not re-filter and
  // re-render the whole table.
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const [srcFilter, setSrcFilter] = useState('');
  const [scoreMin, setScoreMin] = useState(0);
  const [sortCol, setSortCol] = useState('risk_score');
  const [sortDir, setSortDir] = useState(-1);

  useEffect(() => {
    api
      .getReport(runId)
      .then((data) => setReport(data))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [runId]);

  const allFindings = report?.findings || [];
  const summary = report?.summary || {};

  useEffect(() => {
    const timer = setTimeout(() => setQuery(search), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [search]);

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    const result = allFindings.filter((f) => {
      if (sevFilter && f.severity_raw !== sevFilter) return false;
      if (srcFilter && f.source !== srcFilter) return false;
      if (f.risk_score < scoreMin) return false;
      if (q) {
        const haystack = [
          f.title, f.description, f.tool,
          ...(f.cve || []), ...(f.cwe || []),
          fmtLocation(f.location), f.id,
        ].join(' ').toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });

    result.sort((a, b) => {
      let av = a[sortCol], bv = b[sortCol];
      if (sortCol === 'severity_raw') {
        av = SEV_ORDER[av] ?? 99;
        bv = SEV_ORDER[bv] ?? 99;
      }
      if (av < bv) return -1 * sortDir;
      if (av > bv) return 1 * sortDir;
      return 0;
    });
    return result;
  }, [allFindings, query, sevFilter, srcFilter, scoreMin, sortCol, sortDir]);

  // Stable identity, so the memoised rows are not invalidated every render.
  const selectFinding = useCallback((finding) => setModalFinding(finding), []);

  const onSort = (col) => {
    if (sortCol === col) {
      setSortDir((d) => d * -1);
    } else {
      setSortCol(col);
      setSortDir(col === 'risk_score' ? -1 : 1);
    }
  };

  const sortClass = (col) =>
    'sortable-col' + (sortCol === col ? (sortDir === -1 ? ' sorted-desc' : ' sorted-asc') : '');

  const jumpToFinding = (id) => {
    setModalFinding(null);
    const row = document.querySelector(`tr[data-id="${id}"]`);
    if (row) {
      row.scrollIntoView({ behavior: 'smooth', block: 'center' });
      row.style.outline = '2px solid var(--accent)';
      setTimeout(() => (row.style.outline = ''), 2000);
    }
  };

  const exportCSV = () => {
    const headers = ['id', 'severity', 'source', 'tool', 'title', 'location', 'cve', 'cwe', 'risk_score', 'exposure', 'evidence'];
    const rows = allFindings.map((f) => [
      f.id, f.severity_raw, f.source, f.tool,
      `"${(f.title || '').replace(/"/g, '""')}"`,
      `"${fmtLocation(f.location).replace(/"/g, '""')}"`,
      (f.cve || []).join(';'),
      (f.cwe || []).join(';'),
      f.risk_score, f.exposure,
      `"${(f.evidence || '').replace(/"/g, '""')}"`,
    ]);
    const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-${runId}-findings.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const bySev = summary.by_severity || {};
  const sevValues = SEV_LABELS.map((l) => bySev[l] || 0);
  const bySrc = summary.by_source || {};
  const srcLabels = Object.keys(bySrc);
  const srcValues = srcLabels.map((l) => bySrc[l]);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Scan Results <code>{runId}</code></h1>
          <div className="scan-meta">
            {report &&
              `${fmtDate(report.generated_at || '')} · ${report.repo_path || ''} · ${allFindings.length} findings`}
          </div>
        </div>
        <div className="header-actions">
          <Link to={`/scans/${runId}/report`} className="btn btn-secondary">📄 Full Report</Link>
          <button className="btn btn-secondary" onClick={exportCSV}>⬇ Export CSV</button>
          <Link to="/scan/new" className="btn btn-primary">+ New Scan</Link>
        </div>
      </div>

      {report?.executive_summary && (
        <div className="card">
          <div className="card-header"><h2>Executive Summary</h2><span className="badge badge-llm">LLM</span></div>
          <div className="card-body"><div className="prose">{report.executive_summary}</div></div>
        </div>
      )}

      <div className="two-col">
        <div className="card">
          <div className="card-header"><h2>Risk Distribution</h2></div>
          <div className="card-body">
            <BarChart labels={SEV_LABELS} values={sevValues} colors={SEV_COLORS} height={200}
                      title="Findings by severity" />
          </div>
        </div>
        <div className="card">
          <div className="card-header"><h2>By Source</h2></div>
          <div className="card-body">
            {srcLabels.length ? (
              <BarChart labels={srcLabels} values={srcValues} colors={SRC_COLORS} height={200}
                        title="Findings by source" />
            ) : (
              <div className="empty-msg">No data</div>
            )}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Findings <span className="badge badge-neutral">{filtered.length}</span></h2>
          <div className="table-controls">
            <input
              type="text" className="form-control"
              placeholder="🔍 Search title, CVE, CWE, location…"
              value={search} onChange={(e) => setSearch(e.target.value)}
            />
            <select className="form-control-sm" value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
              <option value="">All severities</option>
              {SEV_LABELS.map((s) => <option key={s}>{s}</option>)}
            </select>
            <select className="form-control-sm" value={srcFilter} onChange={(e) => setSrcFilter(e.target.value)}>
              <option value="">All sources</option>
              {['SAST', 'DEPS', 'SECRETS', 'CONTAINER', 'NETWORK'].map((s) => <option key={s}>{s}</option>)}
            </select>
            <div className="score-range">
              <label>Score ≥</label>
              <input
                type="number" className="form-control-xs" min="0" max="100"
                value={scoreMin} onChange={(e) => setScoreMin(parseFloat(e.target.value) || 0)}
              />
            </div>
          </div>
        </div>
        <div className="card-body p-0">
          {loading ? (
            <div className="loading-msg">Loading findings…</div>
          ) : error ? (
            <div className="loading-msg">Failed to load report: {error}</div>
          ) : !filtered.length ? (
            <div className="empty-msg">No findings match the current filters.</div>
          ) : (
            <table className="table table-hover sortable">
              <thead>
                <tr>
                  <SortHeader col="risk_score" label="Score" sortCol={sortCol} sortDir={sortDir}
                              onSort={onSort} sortClass={sortClass} />
                  <SortHeader col="severity_raw" label="Severity" sortCol={sortCol} sortDir={sortDir}
                              onSort={onSort} sortClass={sortClass} />
                  <SortHeader col="source" label="Source" sortCol={sortCol} sortDir={sortDir}
                              onSort={onSort} sortClass={sortClass} />
                  <th scope="col">Title</th>
                  <th scope="col">Location</th>
                  <th scope="col">CVE / CWE</th>
                  <th scope="col">Tool</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((f) => (
                  <FindingRow key={f.id} finding={f} onSelect={selectFinding} />
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <FindingModal finding={modalFinding} onClose={() => setModalFinding(null)} onJump={jumpToFinding} />
    </>
  );
}
