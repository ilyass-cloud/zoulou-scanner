// Database-backed persistence (api keys, users/auth, reports, settings).
// All endpoints require Postgres (DATABASE_URL). When it is not configured the
// pg layer throws DatabaseUnavailable, which we translate to 503.
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import * as db from '../lib/pg.js';

const router = Router();

// Wrap async handlers: DatabaseUnavailable → 503, other errors → 400.
const h = (fn) => async (req, res) => {
  try {
    await fn(req, res);
  } catch (e) {
    if (e instanceof db.DatabaseUnavailable) return res.status(503).json({ error: 'database not configured' });
    res.status(400).json({ error: e.message });
  }
};

function maskSecret(secret) {
  if (!secret) return '';
  if (secret.length <= 8) return '…' + secret.slice(-2);
  return secret.slice(0, 3) + '…' + secret.slice(-4);
}
function publicApiKey(row) {
  const { secret, ...rest } = row;
  return { ...rest, secret_preview: maskSecret(secret) };
}

// ── API keys ────────────────────────────────────────────────
router.get('/api-keys', h(async (_req, res) => {
  res.json((await db.listApiKeys()).map(publicApiKey));
}));
router.post('/api-keys', h(async (req, res) => {
  if (!req.body.name || !req.body.secret) return res.status(400).json({ error: 'name and secret are required' });
  res.status(201).json(publicApiKey(await db.createApiKey(req.body)));
}));
router.put('/api-keys/:id', h(async (req, res) => {
  const row = await db.updateApiKey(Number(req.params.id), req.body);
  if (!row) return res.status(404).json({ error: 'API key not found' });
  res.json(publicApiKey(row));
}));
router.delete('/api-keys/:id', h(async (req, res) => {
  if (await db.deleteApiKey(Number(req.params.id))) return res.json({ deleted: true });
  res.status(404).json({ error: 'API key not found' });
}));
router.get('/api-keys/:id/reveal', h(async (req, res) => {
  const row = await db.getApiKey(Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'API key not found' });
  res.json({ secret: row.secret });
}));

// ── Users ───────────────────────────────────────────────────
router.get('/users', h(async (_req, res) => res.json(await db.listUsers())));
router.post('/users', h(async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';
  if (!username || !password) return res.status(400).json({ error: 'username and password are required' });
  try {
    const row = await db.createUser({
      username,
      email: req.body.email,
      role: req.body.role || 'user',
      is_active: req.body.is_active ?? true,
      password_hash: bcrypt.hashSync(password, 10),
    });
    res.status(201).json(row);
  } catch (e) {
    if (e instanceof db.DatabaseUnavailable) throw e;
    res.status(400).json({ error: `Could not create user: ${e.message}` });
  }
}));
router.put('/users/:id', h(async (req, res) => {
  const fields = {};
  for (const k of ['username', 'email', 'role', 'is_active']) if (k in req.body) fields[k] = req.body[k];
  if (req.body.password) fields.password_hash = bcrypt.hashSync(req.body.password, 10);
  const row = await db.updateUser(Number(req.params.id), fields);
  if (!row) return res.status(404).json({ error: 'User not found' });
  res.json(row);
}));
router.delete('/users/:id', h(async (req, res) => {
  if (await db.deleteUser(Number(req.params.id))) return res.json({ deleted: true });
  res.status(404).json({ error: 'User not found' });
}));

// ── Auth ────────────────────────────────────────────────────
router.post('/auth/login', h(async (req, res) => {
  const user = await db.getUserByUsername((req.body.username || '').trim());
  if (!user || !user.is_active || !bcrypt.compareSync(req.body.password || '', user.password_hash))
    return res.status(401).json({ error: 'Invalid username or password' });
  req.session.user_id = user.id;
  req.session.username = user.username;
  res.json({ id: user.id, username: user.username, role: user.role });
}));
router.post('/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});
router.get('/auth/me', h(async (req, res) => {
  const userId = req.session.user_id;
  if (!userId) return res.status(401).json({ error: 'Not authenticated' });
  const user = await db.getUser(userId);
  if (!user) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json(user);
}));

// ── Reports ─────────────────────────────────────────────────
router.get('/reports', h(async (_req, res) => res.json(await db.listReports())));
router.get('/reports/:runId', h(async (req, res) => {
  const row = await db.getReport(req.params.runId);
  if (!row) return res.status(404).json({ error: 'Report not found' });
  res.json(row);
}));
router.post('/reports', h(async (req, res) => {
  if (!req.body.run_id) return res.status(400).json({ error: 'run_id is required' });
  res.status(201).json(await db.upsertReport(req.body));
}));
router.delete('/reports/:runId', h(async (req, res) => {
  if (await db.deleteReport(req.params.runId)) return res.json({ deleted: true });
  res.status(404).json({ error: 'Report not found' });
}));

// ── Settings ────────────────────────────────────────────────
router.get('/settings', h(async (_req, res) => res.json(await db.listSettings())));
router.get('/settings/:key', h(async (req, res) => {
  const row = await db.getSetting(req.params.key);
  if (!row) return res.status(404).json({ error: 'Setting not found' });
  res.json(row);
}));
router.put('/settings/:key', h(async (req, res) => {
  if (!('value' in req.body)) return res.status(400).json({ error: 'value is required' });
  res.json(await db.setSetting(req.params.key, req.body.value));
}));
router.delete('/settings/:key', h(async (req, res) => {
  if (await db.deleteSetting(req.params.key)) return res.json({ deleted: true });
  res.status(404).json({ error: 'Setting not found' });
}));

export default router;
