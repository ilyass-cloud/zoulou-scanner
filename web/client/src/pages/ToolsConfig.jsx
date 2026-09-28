import { useEffect, useRef, useState } from 'react';
import { api } from '../lib/api.js';
import { catIcon } from '../lib/format.js';

const CATEGORIES = [
  { key: 'all', label: 'All' },
  { key: 'sast', label: '🔍 SAST' },
  { key: 'deps', label: '📦 Deps' },
  { key: 'secrets', label: '🔑 Secrets' },
  { key: 'container', label: '🐳 Container' },
  { key: 'network', label: '🌐 Network' },
];

const EMPTY_FORM = {
  name: '', label: '', category: 'sast', command: '',
  output_format: 'sarif', install_check: '', description: '', timeout_seconds: 300,
};

export default function ToolsConfig() {
  const [tools, setTools] = useState([]);
  const [filter, setFilter] = useState('all');
  const [form, setForm] = useState(EMPTY_FORM);
  const [msg, setMsg] = useState(null); // { type: 'error'|'success', text }
  const [statuses, setStatuses] = useState({}); // name -> { installed, version, failed }
  const formRef = useRef(null);

  const loadTools = async () => {
    try {
      const data = await api.listTools();
      setTools(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('Failed to load tools:', e);
    }
  };

  useEffect(() => {
    loadTools();
  }, []);

  const filtered = filter === 'all' ? tools : tools.filter((t) => t.category === filter);

  const toggleTool = async (name) => {
    try {
      const data = await api.toggleTool(name);
      setTools((cur) => cur.map((t) => (t.name === name ? { ...t, enabled: data.enabled } : t)));
    } catch (e) {
      console.error('Toggle failed:', e);
    }
  };

  const checkInstall = async (name) => {
    setStatuses((cur) => ({ ...cur, [name]: { checking: true } }));
    try {
      const data = await api.checkTool(name);
      setStatuses((cur) => ({ ...cur, [name]: { installed: data.installed, version: data.version } }));
    } catch {
      setStatuses((cur) => ({ ...cur, [name]: { failed: true } }));
    }
  };

  const deleteTool = async (name) => {
    if (!confirm(`Delete tool "${name}"?`)) return;
    try {
      await api.deleteTool(name);
      setTools((cur) => cur.filter((t) => t.name !== name));
    } catch (e) {
      alert('Delete failed: ' + e.message);
    }
  };

  const editTool = (t) => {
    setForm({
      name: t.name,
      label: t.label || '',
      category: t.category,
      command: t.command,
      output_format: t.output_format,
      install_check: t.install_check || '',
      description: t.description || '',
      timeout_seconds: t.timeout_seconds || 300,
    });
    formRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const setField = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const submitTool = async (e) => {
    e.preventDefault();
    const tool = {
      ...form,
      name: form.name.trim(),
      label: form.label.trim(),
      command: form.command.trim(),
      install_check: form.install_check.trim(),
      description: form.description.trim(),
      timeout_seconds: parseInt(form.timeout_seconds, 10) || 300,
      enabled: true,
    };
    if (!tool.name || !tool.command) {
      setMsg({ type: 'error', text: 'Name and command are required.' });
      return;
    }
    try {
      await api.addTool(tool);
      setMsg({ type: 'success', text: `Tool "${tool.name}" saved.` });
      setForm(EMPTY_FORM);
      await loadTools();
    } catch (err) {
      setMsg({ type: 'error', text: err.message || 'Failed to save tool.' });
    }
  };

  return (
    <>
      <div className="page-header">
        <h1>🛠️ Tools Registry</h1>
        <p className="page-subtitle">Configure external scanning tools. Enable the ones you have installed.</p>
      </div>

      <div className="tools-filter" style={{ marginBottom: '1rem', display: 'flex', gap: '.5rem', flexWrap: 'wrap' }}>
        {CATEGORIES.map((c) => (
          <button
            key={c.key}
            className={`btn btn-sm btn-secondary${filter === c.key ? ' active' : ''}`}
            onClick={() => setFilter(c.key)}
          >
            {c.label}
          </button>
        ))}
      </div>

      <div className="plugin-grid" style={{ marginBottom: '2rem' }}>
        {!filtered.length ? (
          <p style={{ color: 'var(--text-muted)', padding: '1rem' }}>No tools in this category.</p>
        ) : (
          filtered.map((t) => {
            const st = statuses[t.name];
            return (
              <div key={t.name} className="plugin-card tool-card" style={{ opacity: t.enabled ? 1 : 0.6 }}>
                <div className="plugin-header">
                  <span className="plugin-icon">{catIcon(t.category)}</span>
                  <span className="plugin-name">{t.label || t.name}</span>
                  <label className="toggle-switch">
                    <input type="checkbox" checked={!!t.enabled} onChange={() => toggleTool(t.name)} />
                    <span className="toggle-slider" />
                  </label>
                </div>
                <div className="plugin-body" style={{ display: 'flex', flexDirection: 'column', gap: '.4rem' }}>
                  <small className="form-hint"><strong>Category:</strong> {t.category.toUpperCase()}</small>
                  <small className="form-hint"><strong>Command:</strong> <code>{t.command}</code></small>
                  <small className="form-hint"><strong>Format:</strong> {t.output_format}</small>
                  {t.description && <small className="form-hint">{t.description}</small>}
                  <div style={{ display: 'flex', gap: '.5rem', marginTop: '.5rem', flexWrap: 'wrap' }}>
                    <button className="btn btn-sm btn-secondary" disabled={st?.checking} onClick={() => checkInstall(t.name)}>
                      {st?.checking ? '⏳ Checking…' : '🔍 Check Install'}
                    </button>
                    <button className="btn btn-sm btn-secondary" onClick={() => editTool(t)}>✏️ Edit</button>
                    <button className="btn btn-sm" style={{ color: 'var(--danger)' }} onClick={() => deleteTool(t.name)}>
                      🗑️ Delete
                    </button>
                  </div>
                  <div className="tool-status" style={{ marginTop: '.3rem' }}>
                    {st && !st.checking && (
                      st.failed ? (
                        <span className="sev-badge sev-high">❌ Check failed</span>
                      ) : st.installed ? (
                        <><span className="sev-badge sev-info">✅ Installed</span> {st.version || ''}</>
                      ) : (
                        <span className="sev-badge sev-high">❌ Not found</span>
                      )
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      <div className="card" style={{ marginBottom: '2rem' }} ref={formRef}>
        <div className="card-header"><h2>➕ Add New Tool</h2></div>
        <div className="card-body">
          <form className="form-grid" onSubmit={submitTool}>
            <div className="form-group">
              <label>Name <span className="required">*</span></label>
              <input type="text" className="form-control" placeholder="my-scanner" value={form.name} onChange={setField('name')} required />
            </div>
            <div className="form-group">
              <label>Label</label>
              <input type="text" className="form-control" placeholder="My Scanner (SAST)" value={form.label} onChange={setField('label')} />
            </div>
            <div className="form-group">
              <label>Category <span className="required">*</span></label>
              <select className="form-control" value={form.category} onChange={setField('category')}>
                <option value="sast">SAST</option>
                <option value="deps">Dependencies</option>
                <option value="secrets">Secrets</option>
                <option value="container">Container</option>
                <option value="network">Network</option>
              </select>
            </div>
            <div className="form-group" style={{ gridColumn: '1/-1' }}>
              <label>Command Template <span className="required">*</span></label>
              <input
                type="text" className="form-control"
                placeholder="scanner --format json -o {output_file} {repo_path}"
                value={form.command} onChange={setField('command')} required
              />
              <small className="form-hint">Variables: {'{repo_path}'}, {'{output_file}'}, {'{output_dir}'}</small>
            </div>
            <div className="form-group">
              <label>Output Format</label>
              <select className="form-control" value={form.output_format} onChange={setField('output_format')}>
                <option value="sarif">SARIF</option>
                <option value="json">JSON</option>
                <option value="xml">XML</option>
                <option value="text">Text</option>
              </select>
            </div>
            <div className="form-group">
              <label>Install Check Command</label>
              <input type="text" className="form-control" placeholder="scanner --version" value={form.install_check} onChange={setField('install_check')} />
            </div>
            <div className="form-group" style={{ gridColumn: '1/-1' }}>
              <label>Description</label>
              <input type="text" className="form-control" placeholder="What this tool does..." value={form.description} onChange={setField('description')} />
            </div>
            <div className="form-group">
              <label>Timeout (seconds)</label>
              <input type="number" className="form-control" min="10" value={form.timeout_seconds} onChange={setField('timeout_seconds')} />
            </div>
            <div className="form-actions" style={{ gridColumn: '1/-1' }}>
              <button type="submit" className="btn btn-primary">Add Tool</button>
            </div>
          </form>
          {msg && (
            <div className={`alert alert-${msg.type}`} style={{ marginTop: '1rem' }}>{msg.text}</div>
          )}
        </div>
      </div>
    </>
  );
}
