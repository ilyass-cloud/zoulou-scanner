/* Thin wrapper around the Express /api/* endpoints.
   Every backend call in the app goes through here so the base path and error
   handling live in one place. */

async function request(path, options = {}) {
  const res = await fetch(`/api${path}`, options);
  const ct = res.headers.get('content-type') || '';
  const body = ct.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) {
    const msg = (body && body.error) || (typeof body === 'string' && body) || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return body;
}

export const api = {
  // ── Scans ──────────────────────────────────────────────────
  listScans: () => request('/scans'),
  getScan: (runId) => request(`/scans/${runId}`),
  getReport: (runId) => request(`/scans/${runId}/report`),
  getReportHtml: (runId) => request(`/scans/${runId}/report.md`),
  cancelScan: (runId) => request(`/scans/${runId}/cancel`, { method: 'POST' }),
  deleteScan: (runId) => request(`/scans/${runId}`, { method: 'DELETE' }),
  startScan: (formData) => request('/scan', { method: 'POST', body: formData }),

  // ── Config / repo helpers ──────────────────────────────────
  listConfigs: () => request('/configs'),
  browse: (path) => request('/browse' + (path ? `?path=${encodeURIComponent(path)}` : '')),
  ignorePatterns: () => request('/ignore-patterns'),
  uploadRepo: (formData) => request('/upload-repo', { method: 'POST', body: formData }),
  autoPlan: (payload) =>
    request('/auto-plan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),

  // ── Saved Git repositories ─────────────────────────────────
  listRepos: () => request('/repos'),
  createRepo: (r) =>
    request('/repos', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(r),
    }),
  updateRepo: (id, r) =>
    request(`/repos/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(r),
    }),
  deleteRepo: (id) => request(`/repos/${id}`, { method: 'DELETE' }),
  testRepo: (id) => request(`/repos/${id}/test`, { method: 'POST' }),
  cloneRepo: (id) => request(`/repos/${id}/clone`, { method: 'POST' }),

  // ── Connected Git accounts (OAuth2) ────────────────────────
  githubStatus: () => request('/git/github/status'),
  connectGithubUrl: () => '/api/git/github/connect', // browser-navigated (full redirect)
  listAccounts: () => request('/git/accounts'),
  deleteAccount: (id) => request(`/git/accounts/${id}`, { method: 'DELETE' }),
  listAccountRepos: (id) => request(`/git/accounts/${id}/repos`),
  cloneAccountRepo: (id, payload) =>
    request(`/git/accounts/${id}/clone`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),

  // ── Authentication ─────────────────────────────────────────
  // whoami() resolves to the user when logged in and null when not, so callers
  // can branch on the answer instead of catching the 401 that /auth/me returns.
  authStatus: () => request('/auth/status'),
  whoami: () => request('/auth/me').catch(() => null),
  login: (username, password) =>
    request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request('/auth/logout', { method: 'POST' }),

  // ── Tools registry ─────────────────────────────────────────
  listTools: () => request('/tools'),
  toggleTool: (name) => request(`/tools/${name}/toggle`, { method: 'POST' }),
  checkTool: (name) => request(`/tools/${name}/check`, { method: 'POST' }),
  deleteTool: (name) => request(`/tools/${name}`, { method: 'DELETE' }),
  addTool: (tool) =>
    request('/tools/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(tool),
    }),
};
