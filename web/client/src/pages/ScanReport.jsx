import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api } from '../lib/api.js';

// The error text is interpolated into HTML that is injected below, unlike the
// report itself, which the server sanitizes. Escape it.
const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export default function ScanReport() {
  const { runId } = useParams();
  const [html, setHtml] = useState('<div class="loading-msg">Loading report…</div>');

  useEffect(() => {
    api
      .getReportHtml(runId)
      .then(setHtml)
      .catch((e) => setHtml(`<div class="alert alert-error">Failed to load report: ${escapeHtml(e.message)}</div>`));
  }, [runId]);

  return (
    <>
      <div className="page-header">
        <h1>Full Report <code>{runId}</code></h1>
        <div className="header-actions">
          <Link to={`/scans/${runId}`} className="btn btn-secondary">← Back to Results</Link>
          <button className="btn btn-secondary" onClick={() => window.print()}>🖨 Print</button>
        </div>
      </div>

      <div className="card">
        {/* report.md is rendered to HTML server-side by the /report.md endpoint. */}
        <div className="card-body report-body" dangerouslySetInnerHTML={{ __html: html }} />
      </div>
    </>
  );
}
