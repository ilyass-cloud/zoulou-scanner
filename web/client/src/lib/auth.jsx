/* Authentication gate.

   The backend guards /api only when it is configured to (see server/lib/auth.js),
   so the client asks /auth/status on boot rather than assuming either way. When
   auth is off this renders its children immediately and the app behaves exactly
   as it did before. */
import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { api } from './api.js';

const AuthContext = createContext({ user: null, logout: async () => {} });

export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }) {
  const [state, setState] = useState({ loading: true, required: false, user: null });

  const refresh = useCallback(async () => {
    try {
      const status = await api.authStatus();
      const user = status.authenticated ? await api.whoami() : null;
      setState({ loading: false, required: status.auth_required, user });
    } catch {
      // Backend unreachable: fail closed only if we cannot tell. Rendering the
      // login form is the safe default — the API would reject the app anyway.
      setState({ loading: false, required: true, user: null });
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const logout = useCallback(async () => {
    try { await api.logout(); } finally { await refresh(); }
  }, [refresh]);

  if (state.loading) return <div className="auth-screen">Loading…</div>;
  if (state.required && !state.user) return <LoginForm onSuccess={refresh} />;

  return (
    <AuthContext.Provider value={{ user: state.user, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

function LoginForm({ onSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(username, password);
      await onSuccess();
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <div className="auth-screen">
      <form className="auth-card" onSubmit={submit}>
        <h1>🔒 Security Orchestrator</h1>
        <p className="form-hint">Sign in to continue.</p>

        <div className="form-group">
          <label htmlFor="auth-username">Username</label>
          <input
            id="auth-username"
            className="form-control"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="auth-password">Password</label>
          <input
            id="auth-password"
            className="form-control"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </div>

        {error && <div className="alert alert-error">{error}</div>}

        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
