// Port of web/db.py: optional PostgreSQL persistence layer.
//
// If DATABASE_URL is unset, every helper throws DatabaseUnavailable, which the
// route layer turns into a clean 503 — so the app runs fine without a database.
import pg from 'pg';

const DATABASE_URL = (process.env.DATABASE_URL || '').trim();

export class DatabaseUnavailable extends Error {}

let pool = null;
export function isEnabled() {
  return Boolean(DATABASE_URL);
}

function getPool() {
  if (!isEnabled()) throw new DatabaseUnavailable('database not configured');
  if (!pool) pool = new pg.Pool({ connectionString: DATABASE_URL });
  return pool;
}

async function q(text, params = []) {
  const res = await getPool().query(text, params);
  return res;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS api_keys (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    provider    TEXT NOT NULL DEFAULT 'custom',
    secret      TEXT NOT NULL,
    base_url    TEXT,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS reports (
    id            SERIAL PRIMARY KEY,
    run_id        TEXT UNIQUE NOT NULL,
    repo_path     TEXT,
    status        TEXT,
    finding_count INTEGER NOT NULL DEFAULT 0,
    summary       TEXT,
    report        JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS repositories (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    branch          TEXT,
    is_private      BOOLEAN NOT NULL DEFAULT FALSE,
    auth_token      TEXT,
    last_scanned_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS git_accounts (
    id            SERIAL PRIMARY KEY,
    provider      TEXT NOT NULL DEFAULT 'github',
    account_login TEXT NOT NULL,
    account_name  TEXT,
    avatar_url    TEXT,
    access_token  TEXT NOT NULL,
    refresh_token TEXT,
    scopes        TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, account_login)
);
`;

export async function initDb() {
  if (!isEnabled()) return false;
  await q(SCHEMA);
  return true;
}

// ── API keys ────────────────────────────────────────────────
export const listApiKeys = async () =>
  (await q('SELECT * FROM api_keys ORDER BY created_at DESC')).rows;

export const getApiKey = async (id) =>
  (await q('SELECT * FROM api_keys WHERE id = $1', [id])).rows[0] || null;

export const createApiKey = async (d) =>
  (await q(
    `INSERT INTO api_keys (name, provider, secret, base_url, is_active)
     VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [d.name, d.provider ?? 'custom', d.secret, d.base_url ?? null, d.is_active ?? true]
  )).rows[0];

export async function updateApiKey(id, d) {
  const allowed = ['name', 'provider', 'secret', 'base_url', 'is_active'];
  const keys = allowed.filter((k) => k in d);
  if (!keys.length) return getApiKey(id);
  const sets = keys.map((k, i) => `${k} = $${i + 1}`).join(', ');
  const vals = keys.map((k) => d[k]);
  vals.push(id);
  return (await q(
    `UPDATE api_keys SET ${sets}, updated_at = now() WHERE id = $${vals.length} RETURNING *`,
    vals
  )).rows[0] || null;
}

export const deleteApiKey = async (id) =>
  (await q('DELETE FROM api_keys WHERE id = $1', [id])).rowCount > 0;

// ── Users ───────────────────────────────────────────────────
const USER_PUBLIC = 'id, username, email, role, is_active, created_at, updated_at';

export const listUsers = async () =>
  (await q(`SELECT ${USER_PUBLIC} FROM users ORDER BY created_at DESC`)).rows;

export const getUser = async (id) =>
  (await q(`SELECT ${USER_PUBLIC} FROM users WHERE id = $1`, [id])).rows[0] || null;

export const getUserByUsername = async (username) =>
  (await q('SELECT * FROM users WHERE username = $1', [username])).rows[0] || null;

export const createUser = async (d) =>
  (await q(
    `INSERT INTO users (username, email, password_hash, role, is_active)
     VALUES ($1,$2,$3,$4,$5) RETURNING ${USER_PUBLIC}`,
    [d.username, d.email ?? null, d.password_hash, d.role ?? 'user', d.is_active ?? true]
  )).rows[0];

export async function updateUser(id, d) {
  const allowed = ['username', 'email', 'password_hash', 'role', 'is_active'];
  const keys = allowed.filter((k) => k in d);
  if (!keys.length) return getUser(id);
  const sets = keys.map((k, i) => `${k} = $${i + 1}`).join(', ');
  const vals = keys.map((k) => d[k]);
  vals.push(id);
  return (await q(
    `UPDATE users SET ${sets}, updated_at = now() WHERE id = $${vals.length} RETURNING ${USER_PUBLIC}`,
    vals
  )).rows[0] || null;
}

export const deleteUser = async (id) =>
  (await q('DELETE FROM users WHERE id = $1', [id])).rowCount > 0;

// ── Reports ─────────────────────────────────────────────────
export const listReports = async () =>
  (await q(
    `SELECT id, run_id, repo_path, status, finding_count, summary, created_at
     FROM reports ORDER BY created_at DESC`
  )).rows;

export const getReport = async (runId) =>
  (await q('SELECT * FROM reports WHERE run_id = $1', [runId])).rows[0] || null;

export const upsertReport = async (d) =>
  (await q(
    `INSERT INTO reports (run_id, repo_path, status, finding_count, summary, report)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (run_id) DO UPDATE SET
       repo_path=EXCLUDED.repo_path, status=EXCLUDED.status,
       finding_count=EXCLUDED.finding_count, summary=EXCLUDED.summary,
       report=EXCLUDED.report
     RETURNING *`,
    [d.run_id, d.repo_path ?? null, d.status ?? null, d.finding_count ?? 0,
     d.summary ?? null, d.report != null ? JSON.stringify(d.report) : null]
  )).rows[0];

export const deleteReport = async (runId) =>
  (await q('DELETE FROM reports WHERE run_id = $1', [runId])).rowCount > 0;

// ── Settings ────────────────────────────────────────────────
export async function listSettings() {
  const rows = (await q('SELECT key, value FROM settings')).rows;
  return Object.fromEntries(rows.map((r) => [r.key, r.value]));
}

export const getSetting = async (key) =>
  (await q('SELECT key, value FROM settings WHERE key = $1', [key])).rows[0] || null;

export const setSetting = async (key, value) =>
  (await q(
    `INSERT INTO settings (key, value) VALUES ($1,$2)
     ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()
     RETURNING key, value`,
    [key, JSON.stringify(value)]
  )).rows[0];

export const deleteSetting = async (key) =>
  (await q('DELETE FROM settings WHERE key = $1', [key])).rowCount > 0;

// ── Repositories (saved Git repos) ──────────────────────────
export const listRepositories = async () =>
  (await q('SELECT * FROM repositories ORDER BY created_at DESC')).rows;

export const getRepository = async (id) =>
  (await q('SELECT * FROM repositories WHERE id = $1', [id])).rows[0] || null;

export const createRepository = async (d) =>
  (await q(
    `INSERT INTO repositories (name, url, branch, is_private, auth_token)
     VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [d.name, d.url, d.branch ?? null, d.is_private ?? false, d.auth_token ?? null]
  )).rows[0];

export async function updateRepository(id, d) {
  const allowed = ['name', 'url', 'branch', 'is_private', 'auth_token'];
  const keys = allowed.filter((k) => k in d);
  if (!keys.length) return getRepository(id);
  const sets = keys.map((k, i) => `${k} = $${i + 1}`).join(', ');
  const vals = keys.map((k) => d[k]);
  vals.push(id);
  return (await q(
    `UPDATE repositories SET ${sets}, updated_at = now() WHERE id = $${vals.length} RETURNING *`,
    vals
  )).rows[0] || null;
}

export const deleteRepository = async (id) =>
  (await q('DELETE FROM repositories WHERE id = $1', [id])).rowCount > 0;

export const touchRepositoryScanned = async (id) =>
  (await q('UPDATE repositories SET last_scanned_at = now() WHERE id = $1 RETURNING *', [id])).rows[0] || null;

// ── Connected Git accounts (OAuth2) ─────────────────────────
export const listGitAccounts = async () =>
  (await q('SELECT * FROM git_accounts ORDER BY created_at DESC')).rows;

export const getGitAccount = async (id) =>
  (await q('SELECT * FROM git_accounts WHERE id = $1', [id])).rows[0] || null;

// Insert or refresh an account's token/profile, keyed by (provider, login).
export const upsertGitAccount = async (d) =>
  (await q(
    `INSERT INTO git_accounts (provider, account_login, account_name, avatar_url, access_token, refresh_token, scopes)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT (provider, account_login) DO UPDATE SET
       account_name=EXCLUDED.account_name, avatar_url=EXCLUDED.avatar_url,
       access_token=EXCLUDED.access_token, refresh_token=EXCLUDED.refresh_token,
       scopes=EXCLUDED.scopes, updated_at=now()
     RETURNING *`,
    [d.provider ?? 'github', d.account_login, d.account_name ?? null, d.avatar_url ?? null,
     d.access_token, d.refresh_token ?? null, d.scopes ?? null]
  )).rows[0];

export const deleteGitAccount = async (id) =>
  (await q('DELETE FROM git_accounts WHERE id = $1', [id])).rowCount > 0;
