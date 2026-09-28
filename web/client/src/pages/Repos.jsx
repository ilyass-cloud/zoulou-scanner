import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../lib/api.js';

const EMPTY_FORM = { name: '', url: '', branch: '', is_private: false, auth_token: '' };

export default function Repos() {
  const [repos, setRepos] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [editingId, setEditingId] = useState(null);
  const [msg, setMsg] = useState(null); // { type: 'error'|'success', text }
  const [tests, setTests] = useState({}); // id -> { testing, ok, error }
  const formRef = useRef(null);

  // ── Connected accounts ──────────────────────────────────────
  const [accounts, setAccounts] = useState([]);
  const [githubConfigured, setGithubConfigured] = useState(true);
  const [searchParams, setSearchParams] = useSearchParams();

  const loadRepos = async () => {
    try {
      setRepos(await api.listRepos());
    } catch (e) {
      setMsg({ type: 'error', text: e.message });
    }
  };

  const loadAccounts = async () => {
    try {
      const [accs, status] = await Promise.all([api.listAccounts(), api.githubStatus()]);
      setAccounts(accs);
      setGithubConfigured(status.configured);
    } catch (e) {
      setMsg({ type: 'error', text: e.message });
    }
  };

  useEffect(() => {
    loadRepos();
    loadAccounts();
  }, []);

  // Surface the result of the OAuth callback redirect, then clean the URL.
  useEffect(() => {
    const connected = searchParams.get('gh_connected');
    const ghError = searchParams.get('gh_error');
    if (connected) setMsg({ type: 'success', text: `Connected GitHub account @${connected}.` });
    else if (ghError) setMsg({ type: 'error', text: `GitHub connection failed: ${ghError}` });
    if (connected || ghError) {
      searchParams.delete('gh_connected');
      searchParams.delete('gh_error');
      setSearchParams(searchParams, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const disconnectAccount = async (acc) => {
    if (!confirm(`Disconnect @${acc.account_login}?`)) return;
    try {
      await api.deleteAccount(acc.id);
      setAccounts((cur) => cur.filter((a) => a.id !== acc.id));
    } catch (e) {
      alert('Disconnect failed: ' + e.message);
    }
  };

  const setField = (k) => (e) =>
    setForm((f) => ({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value }));

  const resetForm = () => {
    setForm(EMPTY_FORM);
    setEditingId(null);
  };

  const editRepo = (r) => {
    setForm({ name: r.name, url: r.url, branch: r.branch || '', is_private: r.is_private, auth_token: '' });
    setEditingId(r.id);
    formRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const submitRepo = async (e) => {
    e.preventDefault();
    const payload = {
      name: form.name.trim(),
      url: form.url.trim(),
      branch: form.branch.trim(),
      is_private: form.is_private,
    };
    if (form.auth_token) payload.auth_token = form.auth_token;
    if (!payload.name || !payload.url) {
      setMsg({ type: 'error', text: 'Name and URL are required.' });
      return;
    }
    try {
      if (editingId) {
        await api.updateRepo(editingId, payload);
        setMsg({ type: 'success', text: `Repository "${payload.name}" updated.` });
      } else {
        await api.createRepo(payload);
        setMsg({ type: 'success', text: `Repository "${payload.name}" saved.` });
      }
      resetForm();
      await loadRepos();
    } catch (err) {
      setMsg({ type: 'error', text: err.message || 'Failed to save repository.' });
    }
  };

  const deleteRepo = async (r) => {
    if (!confirm(`Delete repository "${r.name}"?`)) return;
    try {
      await api.deleteRepo(r.id);
      setRepos((cur) => cur.filter((x) => x.id !== r.id));
    } catch (e) {
      alert('Delete failed: ' + e.message);
    }
  };

  const testRepo = async (r) => {
    setTests((cur) => ({ ...cur, [r.id]: { testing: true } }));
    try {
      const data = await api.testRepo(r.id);
      setTests((cur) => ({ ...cur, [r.id]: { ok: data.ok, error: data.error } }));
    } catch (e) {
      setTests((cur) => ({ ...cur, [r.id]: { ok: false, error: e.message } }));
    }
  };

  return (
    <>
      <div className="page-header">
        <h1>🌿 Repositories</h1>
        <p className="page-subtitle">
          Connect a Git account to browse its repositories, or save individual repos. Both can be
          selected when configuring a scan.
        </p>
      </div>

      {msg && <div className={`alert alert-${msg.type}`} style={{ marginBottom: '1rem' }}>{msg.text}</div>}

      {/* ── Connected accounts ── */}
      <div className="card" style={{ marginBottom: '2rem' }}>
        <div className="card-header"><h2>🔗 Connected Accounts</h2></div>
        <div className="card-body">
          {!githubConfigured && (
            <div className="alert alert-error" style={{ marginBottom: '1rem' }}>
              GitHub OAuth is not configured. Set <code>GITHUB_CLIENT_ID</code> and{' '}
              <code>GITHUB_CLIENT_SECRET</code> (OAuth App callback{' '}
              <code>…/api/git/github/callback</code>) to enable connecting accounts.
            </div>
          )}
          {!accounts.length ? (
            <p style={{ color: 'var(--text-muted)' }}>No accounts connected yet.</p>
          ) : (
            <div className="plugin-grid">
              {accounts.map((a) => (
                <div key={a.id} className="plugin-card">
                  <div className="plugin-header">
                    {a.avatar_url
                      ? <img src={a.avatar_url} alt="" width={20} height={20} style={{ borderRadius: '50%' }} />
                      : <span className="plugin-icon">🐙</span>}
                    <span className="plugin-name">@{a.account_login}</span>
                  </div>
                  <div className="plugin-body" style={{ display: 'flex', flexDirection: 'column', gap: '.4rem' }}>
                    {a.account_name && <small className="form-hint">{a.account_name}</small>}
                    <small className="form-hint"><strong>Provider:</strong> {a.provider}</small>
                    {a.scopes && <small className="form-hint"><strong>Scopes:</strong> {a.scopes}</small>}
                    <div style={{ marginTop: '.5rem' }}>
                      <button className="btn btn-sm" style={{ color: 'var(--danger)' }} onClick={() => disconnectAccount(a)}>
                        🔌 Disconnect
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
          <div style={{ marginTop: '1rem' }}>
            <a className={`btn btn-secondary${githubConfigured ? '' : ' disabled'}`}
               href={githubConfigured ? api.connectGithubUrl() : undefined}
               aria-disabled={!githubConfigured}
               style={githubConfigured ? undefined : { pointerEvents: 'none', opacity: 0.5 }}>
              🐙 Connect GitHub account
            </a>
          </div>
        </div>
      </div>

      <h2 style={{ marginBottom: '1rem' }}>💾 Saved Repositories</h2>
      <div className="plugin-grid" style={{ marginBottom: '2rem' }}>
        {!repos.length ? (
          <p style={{ color: 'var(--text-muted)', padding: '1rem' }}>
            No repositories saved yet. Add one below.
          </p>
        ) : (
          repos.map((r) => {
            const t = tests[r.id];
            return (
              <div key={r.id} className="plugin-card">
                <div className="plugin-header">
                  <span className="plugin-icon">{r.is_private ? '🔒' : '🌿'}</span>
                  <span className="plugin-name">{r.name}</span>
                </div>
                <div className="plugin-body" style={{ display: 'flex', flexDirection: 'column', gap: '.4rem' }}>
                  <small className="form-hint"><strong>URL:</strong> <code>{r.url}</code></small>
                  {r.branch && <small className="form-hint"><strong>Branch:</strong> {r.branch}</small>}
                  <small className="form-hint">
                    <strong>Token:</strong> {r.has_token ? 'stored ✅' : '—'}
                  </small>
                  {r.last_scanned_at && (
                    <small className="form-hint">
                      <strong>Last scanned:</strong> {new Date(r.last_scanned_at).toLocaleString()}
                    </small>
                  )}
                  <div style={{ display: 'flex', gap: '.5rem', marginTop: '.5rem', flexWrap: 'wrap' }}>
                    <button className="btn btn-sm btn-secondary" disabled={t?.testing} onClick={() => testRepo(r)}>
                      {t?.testing ? '⏳ Testing…' : '🔌 Test'}
                    </button>
                    <button className="btn btn-sm btn-secondary" onClick={() => editRepo(r)}>✏️ Edit</button>
                    <button className="btn btn-sm" style={{ color: 'var(--danger)' }} onClick={() => deleteRepo(r)}>
                      🗑️ Delete
                    </button>
                  </div>
                  {t && !t.testing && (
                    <div style={{ marginTop: '.3rem' }}>
                      {t.ok ? (
                        <span className="sev-badge sev-info">✅ Reachable</span>
                      ) : (
                        <span className="sev-badge sev-high" title={t.error}>❌ {t.error || 'Unreachable'}</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      <div className="card" style={{ marginBottom: '2rem' }} ref={formRef}>
        <div className="card-header"><h2>{editingId ? '✏️ Edit Repository' : '➕ Add Repository'}</h2></div>
        <div className="card-body">
          <form className="form-grid" onSubmit={submitRepo}>
            <div className="form-group">
              <label>Name <span className="required">*</span></label>
              <input type="text" className="form-control" placeholder="my-project" value={form.name} onChange={setField('name')} required />
            </div>
            <div className="form-group">
              <label>Git URL (https) <span className="required">*</span></label>
              <input type="text" className="form-control" placeholder="https://github.com/owner/repo.git" value={form.url} onChange={setField('url')} required />
            </div>
            <div className="form-group">
              <label>Branch (optional)</label>
              <input type="text" className="form-control" placeholder="main" value={form.branch} onChange={setField('branch')} />
            </div>
            <div className="form-group form-group-inline">
              <label className="toggle-switch">
                <input type="checkbox" checked={form.is_private} onChange={setField('is_private')} />
                <span className="toggle-slider" />
              </label>
              <span className="toggle-label">Private repository</span>
            </div>
            {form.is_private && (
              <div className="form-group" style={{ gridColumn: '1/-1' }}>
                <label>Access token (PAT){editingId ? ' — leave blank to keep current' : ''}</label>
                <input type="password" className="form-control" autoComplete="new-password" value={form.auth_token} onChange={setField('auth_token')} />
                <small className="form-hint">Stored server-side only; never shown again.</small>
              </div>
            )}
            <div className="form-actions" style={{ gridColumn: '1/-1' }}>
              <button type="submit" className="btn btn-primary">{editingId ? 'Update Repository' : 'Add Repository'}</button>
              {editingId && (
                <button type="button" className="btn btn-secondary" onClick={resetForm}>Cancel</button>
              )}
            </div>
          </form>
        </div>
      </div>
    </>
  );
}
