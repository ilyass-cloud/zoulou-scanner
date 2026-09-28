// Saved Git repositories ("repos I've saved before"): DB-backed CRUD plus a
// reachability test and an on-demand clone that yields a repo_path the scan
// pipeline can consume — same shape as /upload-repo. All endpoints require
// Postgres (DatabaseUnavailable → 503). The auth token is never returned to the
// client and never logged.
import { Router } from 'express';
import * as db from '../lib/pg.js';
import { cloneRepo, lsRemote } from '../lib/git.js';

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

// Strip the secret; expose only whether a token is stored.
function publicRepo(row) {
  const { auth_token, ...rest } = row;
  return { ...rest, has_token: Boolean(auth_token) };
}

function isHttpUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}

// Build a create/update payload from the request body.
function repoFields(body, { partial = false } = {}) {
  const d = {};
  if ('name' in body) d.name = String(body.name || '').trim();
  if ('url' in body) d.url = String(body.url || '').trim();
  if ('branch' in body) d.branch = body.branch ? String(body.branch).trim() : null;
  if ('is_private' in body) d.is_private = Boolean(body.is_private);
  // Only set the token when a non-empty value is provided, so PUT without a
  // token preserves the stored one; an explicit empty string clears it.
  if ('auth_token' in body) d.auth_token = body.auth_token ? String(body.auth_token) : null;
  if (!partial) {
    if (!d.name) throw new Error('name is required');
    if (!d.url || !isHttpUrl(d.url)) throw new Error('a valid http(s) url is required');
  } else if ('url' in d && !isHttpUrl(d.url)) {
    throw new Error('a valid http(s) url is required');
  }
  return d;
}

router.get('/repos', h(async (_req, res) => {
  res.json((await db.listRepositories()).map(publicRepo));
}));

router.post('/repos', h(async (req, res) => {
  const row = await db.createRepository(repoFields(req.body || {}));
  res.status(201).json(publicRepo(row));
}));

router.put('/repos/:id', h(async (req, res) => {
  const fields = repoFields(req.body || {}, { partial: true });
  // Drop auth_token when the client didn't actually send one (keep existing).
  if ('auth_token' in (req.body || {}) && !req.body.auth_token) delete fields.auth_token;
  const row = await db.updateRepository(Number(req.params.id), fields);
  if (!row) return res.status(404).json({ error: 'Repository not found' });
  res.json(publicRepo(row));
}));

router.delete('/repos/:id', h(async (req, res) => {
  if (await db.deleteRepository(Number(req.params.id))) return res.json({ deleted: true });
  res.status(404).json({ error: 'Repository not found' });
}));

router.post('/repos/:id/test', h(async (req, res) => {
  const repo = await db.getRepository(Number(req.params.id));
  if (!repo) return res.status(404).json({ error: 'Repository not found' });
  res.json(await lsRemote(repo));
}));

router.post('/repos/:id/clone', h(async (req, res) => {
  const repo = await db.getRepository(Number(req.params.id));
  if (!repo) return res.status(404).json({ error: 'Repository not found' });
  try {
    const result = await cloneRepo(repo);
    await db.touchRepositoryScanned(repo.id);
    res.json(result);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
}));

export default router;
