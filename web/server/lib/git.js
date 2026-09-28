// Git source support: shallow-clone a saved repository onto the shared scans
// volume so the existing scan pipeline can mount it read-only — exactly like an
// uploaded folder. Private repos authenticate with a token injected into the
// HTTPS URL; that tokenized URL is NEVER logged or returned.
import { spawn } from 'node:child_process';
import path from 'node:path';

import { newUploadDir } from './ignore.js';
import { SCANS_DIR } from './jobManager.js';

// Build the clone URL, injecting the token for private HTTPS repos. Returns
// { cloneUrl, safeUrl } where safeUrl has any credentials masked for logging.
function buildUrls({ url, is_private, auth_token }) {
  let u;
  try {
    u = new URL(url);
  } catch {
    throw new Error(`Invalid repository URL: ${url}`);
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    throw new Error('Only http(s) Git URLs are supported (ssh / git@ not supported).');
  }
  const safeUrl = `${u.protocol}//${u.host}${u.pathname}`;
  if (is_private && auth_token) {
    // Token as username works for GitHub/GitLab PATs over HTTPS.
    u.username = encodeURIComponent(auth_token);
    u.password = '';
  }
  return { cloneUrl: u.toString(), safeUrl };
}

// Derive a friendly directory/repo name from the URL (".../owner/repo.git").
function repoNameFromUrl(url) {
  try {
    const base = path.posix.basename(new URL(url).pathname);
    return base.replace(/\.git$/i, '') || 'repo';
  } catch {
    return 'repo';
  }
}

function runGit(args, { token } = {}) {
  return new Promise((resolve) => {
    const child = spawn('git', args, { env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } });
    let err = '';
    child.stderr.on('data', (c) => { err += c.toString(); });
    child.on('error', (e) => resolve({ code: -1, stderr: e.message, spawnError: e }));
    child.on('close', (code) => {
      // Never leak the token through error text.
      if (token) err = err.split(token).join('***');
      resolve({ code, stderr: err });
    });
  });
}

// Shallow-clone a repo into <scans>/_uploads/<id> and return { repo_path, name }.
export async function cloneRepo(repo, destRoot = newUploadDir(SCANS_DIR)) {
  const { cloneUrl, safeUrl } = buildUrls(repo);
  const name = repo.name || repoNameFromUrl(repo.url);
  const target = path.resolve(destRoot, name);

  const args = ['clone', '--depth', '1', '--single-branch'];
  if (repo.branch) args.push('--branch', repo.branch);
  args.push(cloneUrl, target);

  const res = await runGit(args, { token: repo.auth_token });
  if (res.spawnError && res.spawnError.code === 'ENOENT') {
    throw new Error("git not found on the backend. The web image must install 'git'.");
  }
  if (res.code !== 0) {
    throw new Error(`git clone failed for ${safeUrl}: ${res.stderr.trim() || `exit ${res.code}`}`);
  }
  return { repo_path: path.resolve(target), name };
}

// Reachability / auth check without cloning. Resolves { ok, error? }.
export async function lsRemote(repo) {
  const { cloneUrl, safeUrl } = buildUrls(repo);
  const res = await runGit(['ls-remote', '--heads', cloneUrl], { token: repo.auth_token });
  if (res.spawnError && res.spawnError.code === 'ENOENT') {
    return { ok: false, error: "git not found on the backend. The web image must install 'git'." };
  }
  if (res.code !== 0) {
    return { ok: false, error: `Cannot reach ${safeUrl}: ${res.stderr.trim() || `exit ${res.code}`}` };
  }
  return { ok: true };
}
