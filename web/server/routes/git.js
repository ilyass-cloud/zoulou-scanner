// Connected Git accounts (GitHub OAuth2, authorization-code flow):
//   GET  /api/git/github/status        – is the OAuth app configured?
//   GET  /api/git/github/connect       – redirect the browser to GitHub
//   GET  /api/git/github/callback      – exchange code, store the account
//   GET  /api/git/accounts             – list connected accounts (no tokens)
//   DELETE /api/git/accounts/:id       – disconnect an account
//   GET  /api/git/accounts/:id/repos   – list that account's repositories
//   POST /api/git/accounts/:id/clone   – clone a chosen repo → { repo_path }
import { Router } from 'express';
import crypto from 'node:crypto';

import * as db from '../lib/pg.js';
import * as gh from '../lib/github.js';
import { cloneRepo } from '../lib/git.js';

const router = Router();

const h = (fn) => async (req, res) => {
  try {
    await fn(req, res);
  } catch (e) {
    if (e instanceof db.DatabaseUnavailable) return res.status(503).json({ error: 'database not configured' });
    res.status(400).json({ error: e.message });
  }
};

// Strip the token; expose only the public profile.
function publicAccount(row) {
  const { access_token, refresh_token, ...rest } = row;
  return rest;
}

router.get('/git/github/status', (_req, res) => {
  res.json({ configured: gh.isConfigured() });
});

// Step 1 – send the browser to GitHub's consent screen.
router.get('/git/github/connect', (req, res) => {
  if (!gh.isConfigured()) {
    return res.status(400).send('GitHub OAuth is not configured (set GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET).');
  }
  const state = crypto.randomBytes(16).toString('hex');
  req.session.gh_oauth_state = state;
  res.redirect(gh.authorizeUrl(state));
});

// Step 2 – GitHub redirects back with ?code & ?state.
router.get('/git/github/callback', h(async (req, res) => {
  const { code, state, error, error_description } = req.query;
  const finish = (qs) => res.redirect(`/repos?${qs}`);

  if (error) return finish(`gh_error=${encodeURIComponent(error_description || error)}`);
  if (!code || !state || state !== req.session.gh_oauth_state) {
    return finish('gh_error=' + encodeURIComponent('Invalid OAuth state'));
  }
  delete req.session.gh_oauth_state;

  try {
    const token = await gh.exchangeCode(String(code));
    const user = await gh.fetchUser(token.access_token);
    await db.upsertGitAccount({
      provider: 'github',
      account_login: user.login,
      account_name: user.name,
      avatar_url: user.avatar_url,
      access_token: token.access_token,
      refresh_token: token.refresh_token,
      scopes: token.scopes,
    });
    finish(`gh_connected=${encodeURIComponent(user.login)}`);
  } catch (e) {
    finish('gh_error=' + encodeURIComponent(e.message));
  }
}));

router.get('/git/accounts', h(async (_req, res) => {
  res.json((await db.listGitAccounts()).map(publicAccount));
}));

router.delete('/git/accounts/:id', h(async (req, res) => {
  if (await db.deleteGitAccount(Number(req.params.id))) return res.json({ deleted: true });
  res.status(404).json({ error: 'Account not found' });
}));

router.get('/git/accounts/:id/repos', h(async (req, res) => {
  const acc = await db.getGitAccount(Number(req.params.id));
  if (!acc) return res.status(404).json({ error: 'Account not found' });
  res.json(await gh.listRepos(acc.access_token));
}));

router.post('/git/accounts/:id/clone', h(async (req, res) => {
  const acc = await db.getGitAccount(Number(req.params.id));
  if (!acc) return res.status(404).json({ error: 'Account not found' });
  const cloneUrl = String(req.body?.clone_url || '').trim();
  if (!cloneUrl) return res.status(400).json({ error: 'clone_url is required' });
  try {
    const result = await cloneRepo({
      url: cloneUrl,
      name: req.body.name,
      branch: req.body.branch || null,
      // Authenticate every account clone with the stored token (works for
      // public and private repos alike).
      is_private: true,
      auth_token: acc.access_token,
    });
    res.json(result);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
}));

export default router;
