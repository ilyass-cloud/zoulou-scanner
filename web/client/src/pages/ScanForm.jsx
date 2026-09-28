import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../lib/api.js';
import { catIcon } from '../lib/format.js';
import { buildIgnoreMatcher } from '../lib/ignore.js';

const FILE_PLUGINS = [
  { key: 'sast', label: 'SAST', icon: '🔍' },
  { key: 'deps', label: 'Dependencies', icon: '📦' },
  { key: 'secrets', label: 'Secrets', icon: '🔑' },
  { key: 'container', label: 'Container', icon: '🐳' },
];

export default function ScanForm() {
  const navigate = useNavigate();

  // ── Core fields ────────────────────────────────────────────
  const [repoPath, setRepoPath] = useState('');
  const [outputDir, setOutputDir] = useState('');

  // ── Source: upload a folder or a Git repository ────────────
  const [source, setSource] = useState('upload'); // 'upload' | 'git'
  const [gitMode, setGitMode] = useState('account'); // 'account' | 'saved'
  const [cloning, setCloning] = useState(false);
  const [repoError, setRepoError] = useState('');

  // Saved repos
  const [repos, setRepos] = useState([]);
  const [selectedRepoId, setSelectedRepoId] = useState('');
  const [showAddRepo, setShowAddRepo] = useState(false);
  const [newRepo, setNewRepo] = useState({ name: '', url: '', branch: '', is_private: false, auth_token: '' });

  // Connected accounts → their repos
  const [accounts, setAccounts] = useState([]);
  const [selectedAccountId, setSelectedAccountId] = useState('');
  const [accountRepos, setAccountRepos] = useState([]);
  const [selectedCloneUrl, setSelectedCloneUrl] = useState('');
  const [loadingRepos, setLoadingRepos] = useState(false);

  // ── Plugins ────────────────────────────────────────────────
  const [enabled, setEnabled] = useState({
    sast: true, deps: true, secrets: true, container: true, network: false,
  });
  const pluginFileRefs = {
    sast: useRef(null), deps: useRef(null), secrets: useRef(null), container: useRef(null),
  };
  const allowlistRef = useRef(null);
  const networkInputRef = useRef(null);

  // ── Auto-scan ──────────────────────────────────────────────
  const [autoScan, setAutoScan] = useState(false);
  const [detecting, setDetecting] = useState(false);
  const [profile, setProfile] = useState(null);
  const [suggested, setSuggested] = useState([]); // [{name, label, category, ...}]
  const [selectedTools, setSelectedTools] = useState([]); // names

  // ── LLM ────────────────────────────────────────────────────
  const [llmEnabled, setLlmEnabled] = useState(true);

  // ── Upload / submit / errors ───────────────────────────────
  const repoUploadRef = useRef(null);
  const [uploadStatus, setUploadStatus] = useState(null);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    // The repo upload <input> needs non-standard directory attributes.
    if (repoUploadRef.current) {
      repoUploadRef.current.setAttribute('webkitdirectory', '');
      repoUploadRef.current.setAttribute('directory', '');
    }
  }, []);

  // ── Load saved repos + connected accounts on the Git source ─
  const loadRepos = async () => {
    try {
      setRepos(await api.listRepos());
      setRepoError('');
    } catch (e) {
      setRepoError(e.message);
    }
  };
  const loadAccounts = async () => {
    try {
      setAccounts(await api.listAccounts());
    } catch (e) {
      setRepoError(e.message);
    }
  };
  useEffect(() => {
    if (source === 'git') {
      if (!repos.length) loadRepos();
      if (!accounts.length) loadAccounts();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source]);

  // Load a connected account's repositories when one is selected.
  useEffect(() => {
    if (!selectedAccountId) { setAccountRepos([]); return; }
    setLoadingRepos(true);
    setSelectedCloneUrl('');
    api.listAccountRepos(Number(selectedAccountId))
      .then((rs) => setAccountRepos(rs))
      .catch((e) => setRepoError(e.message))
      .finally(() => setLoadingRepos(false));
  }, [selectedAccountId]);

  // Switching source/mode resets the resolved repo path so stale selections can't leak.
  const switchSource = (next) => {
    setSource(next);
    setRepoPath('');
    setUploadStatus(null);
    setError('');
  };
  const switchGitMode = (next) => {
    setGitMode(next);
    setRepoPath('');
    setUploadStatus(null);
    setRepoError('');
  };

  const onAddRepo = async (e) => {
    e.preventDefault();
    setRepoError('');
    try {
      const created = await api.createRepo(newRepo);
      await loadRepos();
      setSelectedRepoId(String(created.id));
      setShowAddRepo(false);
      setNewRepo({ name: '', url: '', branch: '', is_private: false, auth_token: '' });
    } catch (err) {
      setRepoError(err.message);
    }
  };

  const onFetchRepo = async () => {
    if (!selectedRepoId) {
      setRepoError('Pick a repository first.');
      return;
    }
    setCloning(true);
    setUploadStatus('Cloning repository…');
    try {
      const data = await api.cloneRepo(Number(selectedRepoId));
      setRepoPath(data.repo_path);
      setUploadStatus(`✅ Cloned ${data.name}. Ready to scan.`);
    } catch (err) {
      setRepoPath('');
      setUploadStatus('Clone failed: ' + err.message);
    } finally {
      setCloning(false);
    }
  };

  const onFetchAccountRepo = async () => {
    if (!selectedCloneUrl) {
      setRepoError('Pick a repository first.');
      return;
    }
    const repo = accountRepos.find((r) => r.clone_url === selectedCloneUrl);
    setCloning(true);
    setUploadStatus('Cloning repository…');
    try {
      const data = await api.cloneAccountRepo(Number(selectedAccountId), {
        clone_url: selectedCloneUrl,
        name: repo?.name,
        branch: repo?.default_branch,
      });
      setRepoPath(data.repo_path);
      setUploadStatus(`✅ Cloned ${data.name}. Ready to scan.`);
    } catch (err) {
      setRepoPath('');
      setUploadStatus('Clone failed: ' + err.message);
    } finally {
      setCloning(false);
    }
  };

  // ── Folder upload (filter heavy content, then upload) ──────
  const onRepoFolderSelected = async (e) => {
    const files = Array.from(e.target.files || []);
    if (!files.length) return;

    setUploadStatus('Preparing…');
    let match;
    try {
      match = buildIgnoreMatcher(await api.ignorePatterns());
    } catch (err) {
      setUploadStatus('Could not load ignore list: ' + err.message);
      return;
    }

    const kept = [];
    let skipped = 0;
    for (const f of files) {
      const rel = f.webkitRelativePath || f.name;
      if (match(rel)) { skipped++; continue; }
      kept.push({ f, rel });
    }
    if (!kept.length) {
      setUploadStatus(`All ${files.length} files were filtered out.`);
      return;
    }

    const fd = new FormData();
    for (const { f, rel } of kept) {
      fd.append('files', f, f.name);
      fd.append('paths', rel);
    }

    setUploadStatus(`Uploading ${kept.length} files (skipped ${skipped})…`);
    setSubmitting(true);
    try {
      const data = await api.uploadRepo(fd);
      setRepoPath(data.repo_path);
      setUploadStatus(
        `✅ Uploaded ${data.name} — ${data.file_count} files (skipped ${data.skipped}). Ready to scan.`
      );
    } catch (err) {
      setUploadStatus('Upload failed: ' + err.message);
    } finally {
      setSubmitting(false);
    }
  };

  // ── Auto-scan detection ────────────────────────────────────
  const runDetection = async () => {
    if (!repoPath.trim()) {
      alert('Please upload a project folder first.');
      return;
    }
    setDetecting(true);
    try {
      const data = await api.autoPlan({ repo_path: repoPath.trim(), use_llm: llmEnabled });
      if (data.error) {
        alert('Detection error: ' + data.error);
        return;
      }
      setProfile(data.profile);
      const sel = data.selected_tools || [];
      setSuggested(sel);
      setSelectedTools(sel.map((t) => t.name));
    } catch (e) {
      alert('Detection failed: ' + e.message);
    } finally {
      setDetecting(false);
    }
  };

  const toggleSuggested = (name, checked) => {
    setSelectedTools((cur) =>
      checked ? (cur.includes(name) ? cur : [...cur, name]) : cur.filter((n) => n !== name)
    );
  };

  // ── Submit ─────────────────────────────────────────────────
  const onSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!repoPath.trim()) {
      setError('Please upload a project folder first.');
      return;
    }
    if (enabled.network && !allowlistRef.current?.files?.length) {
      setError(
        '⚠️ Network plugin is enabled but no allowlist file was provided. ' +
          'An allowlist is required to enable network scanning. ' +
          'Only scan targets you are authorized to scan.'
      );
      return;
    }

    const fd = new FormData();
    fd.append('repo_path', repoPath.trim());
    if (outputDir.trim()) fd.append('output_dir', outputDir.trim());

    for (const { key } of FILE_PLUGINS) {
      if (enabled[key]) fd.append(`plugin_enabled_${key}`, 'on');
      const f = pluginFileRefs[key].current?.files?.[0];
      if (f) fd.append(`plugin_file_${key}`, f);
    }
    if (enabled.network) fd.append('plugin_enabled_network', 'on');
    const allow = allowlistRef.current?.files?.[0];
    if (allow) fd.append('network_allowlist_file', allow);
    const netIn = networkInputRef.current?.files?.[0];
    if (netIn) fd.append('network_input_file', netIn);

    if (autoScan) fd.append('auto_scan', 'on');
    if (selectedTools.length) fd.append('selected_tools', selectedTools.join(','));
    if (llmEnabled) fd.append('llm_enabled', 'on');

    setSubmitting(true);
    try {
      const data = await api.startScan(fd);
      navigate(`/scan/${data.run_id}/live`);
    } catch (err) {
      setError(err.message || 'Failed to start scan.');
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="page-header"><h1>Configure New Scan</h1></div>

      <div className="warning-banner">
        ⚠️ <strong>Network Scanning Notice:</strong> The network plugin only scans targets explicitly
        listed in an allowlist file. You must have <strong>written authorization</strong> to scan every
        target. Unauthorized scanning is illegal in most jurisdictions.
      </div>

      <form onSubmit={onSubmit} encType="multipart/form-data">
        {/* ── Core settings ── */}
        <div className="card">
          <div className="card-header"><h2>Core Settings</h2></div>
          <div className="card-body form-grid">
            <div className="form-group">
              <label>Source <span className="required">*</span></label>
              <div className="form-group-inline" style={{ gap: '1rem', marginBottom: '.5rem' }}>
                <label className="toggle-label" style={{ cursor: 'pointer' }}>
                  <input
                    type="radio" name="source" value="upload"
                    checked={source === 'upload'} onChange={() => switchSource('upload')}
                  />{' '}📁 Upload a project
                </label>
                <label className="toggle-label" style={{ cursor: 'pointer' }}>
                  <input
                    type="radio" name="source" value="git"
                    checked={source === 'git'} onChange={() => switchSource('git')}
                  />{' '}🌿 From a Git repository
                </label>
              </div>

              {source === 'upload' ? (
                <>
                  <input
                    type="file" id="repo_upload" multiple className="form-control-sm"
                    ref={repoUploadRef} onChange={onRepoFolderSelected}
                  />
                  <small className="form-hint">
                    Select the project folder to scan. Heavy folders (node_modules, .venv, .git,
                    build outputs, binaries, media…) are skipped automatically before upload;
                    manifests &amp; lockfiles are kept.
                  </small>
                </>
              ) : (
                <>
                  <div className="form-group-inline" style={{ gap: '1rem', marginBottom: '.5rem' }}>
                    <label className="toggle-label" style={{ cursor: 'pointer' }}>
                      <input
                        type="radio" name="gitmode" value="account"
                        checked={gitMode === 'account'} onChange={() => switchGitMode('account')}
                      />{' '}🔗 Connected account
                    </label>
                    <label className="toggle-label" style={{ cursor: 'pointer' }}>
                      <input
                        type="radio" name="gitmode" value="saved"
                        checked={gitMode === 'saved'} onChange={() => switchGitMode('saved')}
                      />{' '}💾 Saved repository
                    </label>
                  </div>

                  {gitMode === 'account' && (
                    <>
                      {!accounts.length ? (
                        <small className="form-hint">
                          No connected accounts. <Link to="/repos">Connect a GitHub account</Link>.
                        </small>
                      ) : (
                        <div style={{ display: 'flex', gap: '.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                          <select
                            className="form-control" style={{ minWidth: 180 }}
                            value={selectedAccountId} onChange={(e) => setSelectedAccountId(e.target.value)}
                          >
                            <option value="">— Account —</option>
                            {accounts.map((a) => (
                              <option key={a.id} value={a.id}>@{a.account_login}</option>
                            ))}
                          </select>
                          <select
                            className="form-control" style={{ flex: 1, minWidth: 220 }}
                            value={selectedCloneUrl} onChange={(e) => setSelectedCloneUrl(e.target.value)}
                            disabled={!selectedAccountId || loadingRepos}
                          >
                            <option value="">
                              {loadingRepos ? 'Loading repositories…' : '— Select a repository —'}
                            </option>
                            {accountRepos.map((r) => (
                              <option key={r.clone_url} value={r.clone_url}>
                                {r.full_name}{r.private ? ' 🔒' : ''}
                              </option>
                            ))}
                          </select>
                          <button
                            type="button" className="btn btn-secondary"
                            disabled={cloning || !selectedCloneUrl} onClick={onFetchAccountRepo}
                          >
                            {cloning ? '⏳ Cloning…' : '⬇️ Fetch repository'}
                          </button>
                        </div>
                      )}
                      <small className="form-hint">
                        Repositories are listed live from the connected account.{' '}
                        <Link to="/repos">Manage accounts</Link>.
                      </small>
                    </>
                  )}

                  {gitMode === 'saved' && (
                  <>
                  <div style={{ display: 'flex', gap: '.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                    <select
                      className="form-control" style={{ flex: 1, minWidth: 220 }}
                      value={selectedRepoId} onChange={(e) => setSelectedRepoId(e.target.value)}
                    >
                      <option value="">— Select a saved repository —</option>
                      {repos.map((r) => (
                        <option key={r.id} value={r.id}>
                          {r.name} ({r.url}{r.branch ? `#${r.branch}` : ''}){r.is_private ? ' 🔒' : ''}
                        </option>
                      ))}
                    </select>
                    <button
                      type="button" className="btn btn-secondary"
                      disabled={cloning || !selectedRepoId} onClick={onFetchRepo}
                    >
                      {cloning ? '⏳ Cloning…' : '⬇️ Fetch repository'}
                    </button>
                    <button
                      type="button" className="btn btn-secondary"
                      onClick={() => setShowAddRepo((v) => !v)}
                    >
                      {showAddRepo ? '✕ Cancel' : '+ Add repository'}
                    </button>
                  </div>
                  <small className="form-hint">
                    Repositories are saved in the database for reuse.{' '}
                    <Link to="/repos">Manage repositories</Link>.
                  </small>

                  {showAddRepo && (
                    <div className="card" style={{ background: 'var(--bg-secondary)', marginTop: '.75rem' }}>
                      <div className="card-body form-grid">
                        <div className="form-group">
                          <label className="form-label-sm">Name <span className="required">*</span></label>
                          <input
                            type="text" className="form-control-sm" value={newRepo.name}
                            onChange={(e) => setNewRepo((s) => ({ ...s, name: e.target.value }))}
                          />
                        </div>
                        <div className="form-group">
                          <label className="form-label-sm">Git URL (https) <span className="required">*</span></label>
                          <input
                            type="text" className="form-control-sm" placeholder="https://github.com/owner/repo.git"
                            value={newRepo.url}
                            onChange={(e) => setNewRepo((s) => ({ ...s, url: e.target.value }))}
                          />
                        </div>
                        <div className="form-group">
                          <label className="form-label-sm">Branch (optional)</label>
                          <input
                            type="text" className="form-control-sm" placeholder="main"
                            value={newRepo.branch}
                            onChange={(e) => setNewRepo((s) => ({ ...s, branch: e.target.value }))}
                          />
                        </div>
                        <div className="form-group form-group-inline">
                          <label className="toggle-switch">
                            <input
                              type="checkbox" checked={newRepo.is_private}
                              onChange={(e) => setNewRepo((s) => ({ ...s, is_private: e.target.checked }))}
                            />
                            <span className="toggle-slider" />
                          </label>
                          <span className="toggle-label">Private repository</span>
                        </div>
                        {newRepo.is_private && (
                          <div className="form-group">
                            <label className="form-label-sm">Access token (PAT)</label>
                            <input
                              type="password" className="form-control-sm" autoComplete="new-password"
                              value={newRepo.auth_token}
                              onChange={(e) => setNewRepo((s) => ({ ...s, auth_token: e.target.value }))}
                            />
                            <small className="form-hint">Stored server-side only; never shown again.</small>
                          </div>
                        )}
                        <div className="form-actions" style={{ marginTop: 0 }}>
                          <button type="button" className="btn btn-primary" onClick={onAddRepo}>Save repository</button>
                        </div>
                      </div>
                    </div>
                  )}
                  </>
                  )}
                  {repoError && <div className="alert alert-error" style={{ marginTop: '.5rem' }}>{repoError}</div>}
                </>
              )}

              {uploadStatus && (
                <div className="form-hint" style={{ marginTop: '.5rem' }}>{uploadStatus}</div>
              )}
            </div>

            <div className="form-group">
              <label htmlFor="output_dir">Output Directory</label>
              <input
                type="text" id="output_dir" className="form-control"
                placeholder="scans/ (auto-managed)"
                value={outputDir} onChange={(e) => setOutputDir(e.target.value)}
              />
              <small className="form-hint">Leave blank — the GUI manages output directories automatically.</small>
            </div>
          </div>
        </div>

        {/* ── Plugins ── */}
        <div className="card">
          <div className="card-header"><h2>Plugins</h2></div>
          <div className="card-body">
            <div className="plugin-grid">
              {FILE_PLUGINS.map(({ key, label, icon }) => (
                <div key={key} className="plugin-card">
                  <div className="plugin-header">
                    <span className="plugin-icon">{icon}</span>
                    <span className="plugin-name">{label}</span>
                    <label className="toggle-switch">
                      <input
                        type="checkbox" checked={enabled[key]}
                        onChange={(e) => setEnabled((s) => ({ ...s, [key]: e.target.checked }))}
                      />
                      <span className="toggle-slider" />
                    </label>
                  </div>
                  <div className="plugin-body" style={{ opacity: enabled[key] ? 1 : 0.4 }}>
                    <label className="form-label-sm">Input file (optional override)</label>
                    <input
                      type="file" className="form-control-sm" ref={pluginFileRefs[key]}
                      accept=".json,.sarif,.sarif.json,.xml"
                    />
                    <small className="form-hint">Leave blank to run the plugin's default scan.</small>
                  </div>
                </div>
              ))}

              {/* Network plugin (special) */}
              <div className="plugin-card plugin-card-network">
                <div className="plugin-header">
                  <span className="plugin-icon">🌐</span>
                  <span className="plugin-name">Network</span>
                  <label className="toggle-switch">
                    <input
                      type="checkbox" checked={enabled.network}
                      onChange={(e) => setEnabled((s) => ({ ...s, network: e.target.checked }))}
                    />
                    <span className="toggle-slider" />
                  </label>
                </div>
                {enabled.network && (
                  <div className="plugin-body" style={{ display: 'flex', flexDirection: 'column' }}>
                    <div className="warning-inline">
                      ⚠️ Only scan targets you are <strong>authorized</strong> to scan.
                    </div>
                    <label className="form-label-sm">Allowlist file <span className="required">*</span></label>
                    <input type="file" ref={allowlistRef} className="form-control-sm" accept=".txt" />
                    <small className="form-hint">One IP/hostname per line. CIDR requires config flag.</small>

                    <label className="form-label-sm" style={{ marginTop: '.75rem' }}>nmap XML (parse-only mode)</label>
                    <input type="file" ref={networkInputRef} className="form-control-sm" accept=".xml" />
                    <small className="form-hint">Upload a pre-captured nmap XML to avoid live scanning.</small>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* ── Auto-Scan ── */}
        <div className="card">
          <div className="card-header"><h2>🤖 Auto-Scan (Smart Detection)</h2></div>
          <div className="card-body">
            <div className="form-group form-group-inline" style={{ marginBottom: '1rem' }}>
              <label className="toggle-switch">
                <input type="checkbox" checked={autoScan} onChange={(e) => setAutoScan(e.target.checked)} />
                <span className="toggle-slider" />
              </label>
              <span className="toggle-label">
                Enable auto-scan: detect repo environment and automatically select appropriate tools
              </span>
            </div>
            {autoScan && (
              <div>
                <button type="button" className="btn btn-secondary" disabled={detecting} onClick={runDetection}>
                  {detecting ? '⏳ Detecting…' : '🔍 Detect Environment'}
                </button>
                {profile && (
                  <div style={{ marginTop: '1rem' }}>
                    <div className="card" style={{ background: 'var(--bg-secondary)' }}>
                      <div className="card-body">
                        <h3 style={{ marginBottom: '.5rem' }}>Detected Environment</h3>
                        <div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '.5rem', marginBottom: '.5rem' }}>
                            {(profile.languages || []).map((l) => <span key={l} className="sev-badge sev-info">{l}</span>)}
                            {(profile.frameworks || []).map((f) => <span key={f} className="sev-badge sev-low">{f}</span>)}
                            {(profile.package_managers || []).map((p) => <span key={p} className="sev-badge sev-medium">{p}</span>)}
                            {profile.has_dockerfile && <span className="sev-badge sev-high">🐳 Docker</span>}
                            {profile.has_kubernetes && <span className="sev-badge sev-high">☸ K8s</span>}
                            {profile.has_terraform && <span className="sev-badge sev-high">🏗️ Terraform</span>}
                          </div>
                          <small className="form-hint">{profile.summary}</small>
                        </div>
                        <h3 style={{ margin: '1rem 0 .5rem' }}>Suggested Tools</h3>
                        <div className="plugin-grid">
                          {suggested.length ? (
                            suggested.map((t) => (
                              <div key={t.name} className="plugin-card" style={{ minWidth: 200 }}>
                                <div className="plugin-header">
                                  <span className="plugin-icon">{catIcon(t.category)}</span>
                                  <span className="plugin-name">{t.label || t.name}</span>
                                  <label className="toggle-switch">
                                    <input
                                      type="checkbox" checked={selectedTools.includes(t.name)}
                                      onChange={(e) => toggleSuggested(t.name, e.target.checked)}
                                    />
                                    <span className="toggle-slider" />
                                  </label>
                                </div>
                                <div className="plugin-body">
                                  <small className="form-hint">{t.description || t.command}</small>
                                </div>
                              </div>
                            ))
                          ) : (
                            <p style={{ color: 'var(--text-muted)' }}>
                              No tools suggested. Enable tools in the <Link to="/tools">Tools Registry</Link>.
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ── LLM ── */}
        <div className="card">
          <div className="card-header"><h2>LLM Analysis</h2></div>
          <div className="card-body form-grid">
            <div className="form-group form-group-inline">
              <label className="toggle-switch">
                <input type="checkbox" checked={llmEnabled} onChange={(e) => setLlmEnabled(e.target.checked)} />
                <span className="toggle-slider" />
              </label>
              <span className="toggle-label">Enable LLM analysis (requires LM Studio running)</span>
            </div>
          </div>
        </div>

        {/* ── Submit ── */}
        <div className="form-actions">
          <button type="submit" className="btn btn-primary btn-lg" disabled={submitting}>
            {submitting ? '⏳ Starting…' : '🚀 Start Scan'}
          </button>
          <Link to="/" className="btn btn-secondary btn-lg">Cancel</Link>
        </div>

        {error && <div className="alert alert-error">{error}</div>}
      </form>
    </>
  );
}
