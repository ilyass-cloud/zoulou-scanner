/* Pure formatting helpers shared across pages (ported from static/js/main.js).
   No DOM here — React handles escaping, so the old escHtml/escAttr are gone. */

export const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, UNKNOWN: 5 };

export const STATUS_BADGE_CLASS = {
  running: 'badge-running',
  done: 'badge-done',
  error: 'badge-error',
  pending: 'badge-pending',
  cancelled: 'badge-cancelled',
};

export function fmtDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function fmtDuration(startIso, endIso) {
  if (!startIso || !endIso) return '—';
  const ms = new Date(endIso) - new Date(startIso);
  if (ms < 0) return '—';
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}

export function fmtLocation(loc) {
  if (!loc) return '—';
  switch (loc.kind) {
    case 'code':
      return `${loc.file_path}${loc.start_line ? ':' + loc.start_line : ''}`;
    case 'deps':
      return `${loc.package_name}@${loc.package_version || '?'} (${loc.manifest_path})`;
    case 'container':
      return `${loc.image_ref} › ${loc.package_name}@${loc.package_version || '?'}`;
    case 'network':
      return `${loc.host}:${loc.port || '?'}/${loc.protocol || 'tcp'}`;
    default:
      return JSON.stringify(loc);
  }
}

export const CATEGORY_ICONS = {
  sast: '🔍',
  deps: '📦',
  secrets: '🔑',
  container: '🐳',
  network: '🌐',
};

export const catIcon = (cat) => CATEGORY_ICONS[cat] || '🔧';
