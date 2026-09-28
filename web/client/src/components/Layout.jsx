import { NavLink, Link } from 'react-router-dom';
import { useTheme } from '../lib/theme.jsx';
import { useAuth } from '../lib/auth.jsx';

const NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/scan/new', label: 'New Scan' },
  { to: '/scans', label: 'Scan History' },
  { to: '/repos', label: 'Repositories' },
  { to: '/tools', label: 'Tools' },
];

export default function Layout({ children }) {
  const { theme, toggleTheme } = useTheme();
  const { user, logout } = useAuth();

  return (
    <>
      {/* WCAG 2.4.1: lets a keyboard user jump past the nav on every page. */}
      <a className="skip-link" href="#main-content">Skip to main content</a>

      <nav className="navbar" aria-label="Main">
        <div className="nav-brand">
          <span className="nav-icon">🔒</span>
          <Link to="/" className="nav-title">Security Orchestrator</Link>
        </div>
        <div className="nav-links">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
            >
              {n.label}
            </NavLink>
          ))}
        </div>
        <div className="nav-actions">
          {user && (
            <span className="nav-user">
              {user.username}
              <button className="btn btn-secondary btn-sm" onClick={logout}>Sign out</button>
            </span>
          )}
          {/* An emoji is not an accessible name, and `title` is unreliable as
              one; aria-pressed exposes which mode is currently active. */}
          <button
            id="theme-toggle"
            className="btn-icon"
            onClick={toggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-pressed={theme === 'dark'}
          >
            <span aria-hidden="true">{theme === 'dark' ? '☀️' : '🌙'}</span>
          </button>
        </div>
      </nav>

      <main className="main-content" id="main-content" tabIndex={-1}>{children}</main>

      <footer className="footer">
        <span>
          Security Orchestrator · Local-only deployment ·{' '}
          <a href="https://github.com" target="_blank" rel="noopener noreferrer">Docs</a>
        </span>
      </footer>
    </>
  );
}
