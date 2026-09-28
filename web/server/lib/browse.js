// Port of web/browse.py: server-side directory browser for picking a scan
// target, jailed to a single root (BROWSE_ROOT, else WORKSPACE_DIR, else $HOME).
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const REPO_MARKERS = [
  '.git', 'package.json', 'package-lock.json', 'yarn.lock',
  'requirements.txt', 'pyproject.toml', 'setup.py', 'Pipfile',
  'go.mod', 'Cargo.toml', 'pom.xml', 'build.gradle', 'settings.gradle',
  'composer.json', 'Gemfile', 'Dockerfile',
];

export function getBrowseRoot() {
  for (const env of ['BROWSE_ROOT', 'WORKSPACE_DIR']) {
    const val = process.env[env];
    try {
      if (val && fs.statSync(val).isDirectory()) return path.resolve(val);
    } catch { /* not a dir */ }
  }
  return path.resolve(os.homedir());
}

export function within(child, root) {
  const c = path.resolve(child);
  const r = path.resolve(root);
  return c === r || c.startsWith(r + path.sep);
}

function isRepo(p) {
  try {
    return REPO_MARKERS.some((m) => fs.existsSync(path.join(p, m)));
  } catch {
    return false;
  }
}

export function listDir(reqPath) {
  const root = getBrowseRoot();

  let target = root;
  if (reqPath) {
    try {
      const candidate = path.resolve(reqPath);
      if (within(candidate, root) && fs.statSync(candidate).isDirectory()) target = candidate;
    } catch { /* fall back to root */ }
  }

  let entries = [];
  try {
    const children = fs.readdirSync(target, { withFileTypes: true })
      .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
    for (const child of children) {
      try {
        if (!child.isDirectory() || child.name.startsWith('.')) continue;
        const full = path.join(target, child.name);
        entries.push({ name: child.name, path: full, is_repo: isRepo(full) });
      } catch { /* skip unreadable */ }
    }
  } catch (e) {
    return { error: String(e.message || e), root, path: target, parent: null, entries: [] };
  }

  let parent = null;
  const up = path.dirname(target);
  if (target !== root && within(up, root)) parent = up;

  return { root, path: target, parent, entries };
}
