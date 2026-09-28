// Session authentication guard for the /api surface.
//
// The backend already had working auth primitives (bcrypt, a users table, and
// the /auth/login|logout|me endpoints in routes/db.js) but nothing enforced
// them: every route was reachable unauthenticated. Since /api/tools/add writes
// a shell command into the tools registry and /api/scan executes it, that was a
// remote code execution path. This module closes it.
//
// Enforcement is opt-out rather than unconditional so the existing demo and
// `docker compose` flow keep working: users live in Postgres, so requiring a
// login with no DATABASE_URL configured would lock everyone out of an app that
// has no way to authenticate them. Hence the default below.
import bcrypt from 'bcryptjs';

import * as db from './pg.js';

const TRUTHY = new Set(['1', 'true', 'on', 'yes']);
const FALSY = new Set(['0', 'false', 'off', 'no']);

// Endpoints that must stay reachable while logged out, otherwise there is no
// way to log in. /auth/me guards itself (it 401s when there is no session).
// /auth/status is public so a logged-out client can tell "auth is off, go
// straight in" apart from "auth is on, show the login form" — a bare 401 from
// /auth/me cannot distinguish the two.
const PUBLIC_PATHS = new Set(['/auth/login', '/auth/logout', '/auth/me', '/auth/status']);

/**
 * Whether a valid session is required to reach /api.
 *
 * REQUIRE_AUTH, when set, wins outright. Otherwise auth is enabled exactly when
 * a database is configured — that is the only case where credentials can exist.
 */
export function authRequired() {
  const raw = (process.env.REQUIRE_AUTH || '').trim().toLowerCase();
  if (TRUTHY.has(raw)) return true;
  if (FALSY.has(raw)) return false;
  return Boolean(process.env.DATABASE_URL);
}

/** Express middleware: reject unauthenticated requests to guarded endpoints. */
export function requireAuth(req, res, next) {
  if (!authRequired()) return next();
  if (PUBLIC_PATHS.has(req.path)) return next();
  if (req.session?.user_id) return next();
  return res.status(401).json({ error: 'Authentication required' });
}

/**
 * Create the first admin account so enabling auth cannot lock the operator out.
 *
 * Only ever runs when the users table is empty, so it will not clobber or reset
 * a real account. Returns the username created, or null if it did nothing.
 */
export async function ensureBootstrapAdmin() {
  if (!authRequired() || !process.env.DATABASE_URL) return null;

  const username = (process.env.ADMIN_USERNAME || '').trim();
  const password = process.env.ADMIN_PASSWORD || '';
  if (!username || !password) return null;

  const existing = await db.listUsers();
  if (existing.length) return null;

  await db.createUser({
    username,
    email: process.env.ADMIN_EMAIL || null,
    password_hash: bcrypt.hashSync(password, 10),
    role: 'admin',
  });
  return username;
}
