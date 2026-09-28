import { STATUS_BADGE_CLASS } from '../lib/format.js';

export function SeverityBadge({ severity }) {
  const s = (severity || 'UNKNOWN').toUpperCase();
  return <span className={`sev sev-${s}`}>{s}</span>;
}

export function StatusBadge({ status }) {
  const cls = STATUS_BADGE_CLASS[status] || 'badge-neutral';
  return <span className={`badge ${cls}`}>{status}</span>;
}

export function ScoreBar({ score }) {
  const pct = Math.round(score || 0);
  const color = pct >= 70 ? '#ef4444' : pct >= 40 ? '#f59e0b' : '#3b82f6';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '.4rem' }}>
      <div style={{ flex: 1, height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontSize: '.8rem', fontWeight: 600, minWidth: 28 }}>{pct}</span>
    </div>
  );
}
