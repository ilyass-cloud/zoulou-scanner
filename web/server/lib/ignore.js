// Port of web/upload.py: the single source of truth for the upload ignore list
// and the server-side save logic. Drops installed dependency trees and binary
// artifacts but always keeps manifests + lockfiles.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { UPLOADS_SUBDIR } from '../config.js';

export const IGNORE_DIRS = new Set([
  '.git', '.hg', '.svn', '.bzr',
  '__pycache__', '.venv', 'venv', '.tox', '.nox', '.mypy_cache',
  '.pytest_cache', '.ruff_cache', '.hypothesis', '.eggs', 'site-packages',
  '.ipynb_checkpoints',
  'node_modules', 'bower_components', '.next', '.nuxt', '.svelte-kit',
  '.angular', '.parcel-cache', '.turbo', '.yarn', '.pnp', '.nyc_output',
  'target', '.gradle', '.m2', 'out',
  'obj', 'packages',
  'vendor', '.bundle',
  '.dart_tool',
  '.build', 'DerivedData', 'Pods', 'Carthage',
  'build', 'dist', 'bin', 'coverage', '.cache', 'cache',
  'tmp', 'temp', 'logs', 'log',
  '.terraform', '.serverless',
  '.idea', '.vscode', '.vs', '.settings', '.history', '__MACOSX',
  '.docker',
]);

export const IGNORE_FILE_NAMES = new Set([
  '.DS_Store', 'Thumbs.db', 'desktop.ini', 'npm-debug.log', 'yarn-error.log',
]);

export const IGNORE_FILE_SUFFIXES = [
  '.min.js', '.min.css', '.map', '.bundle.js',
  '.pyc', '.pyo', '.class', '.o', '.obj', '.so', '.dylib', '.dll', '.exe',
  '.a', '.lib', '.jar', '.war', '.ear', '.nupkg', '.whl', '.egg',
  '.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.rar', '.7z', '.iso',
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
  '.mp3', '.mp4', '.mov', '.avi', '.mkv', '.wav', '.flac',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.pdf', '.bin', '.dat', '.db', '.sqlite', '.sqlite3', '.mo',
];

export function isIgnored(relpath) {
  const parts = relpath.split('/');
  for (const seg of parts.slice(0, -1)) {
    if (IGNORE_DIRS.has(seg)) return true;
  }
  const base = parts[parts.length - 1];
  if (IGNORE_FILE_NAMES.has(base)) return true;
  const lower = base.toLowerCase();
  return IGNORE_FILE_SUFFIXES.some((s) => lower.endsWith(s));
}

export function ignorePatternsPayload() {
  return {
    dirs: [...IGNORE_DIRS].sort(),
    file_names: [...IGNORE_FILE_NAMES].sort(),
    file_suffixes: IGNORE_FILE_SUFFIXES,
  };
}

// Allocate a fresh upload destination under <scansDir>/_uploads/<id>.
export function newUploadDir(scansDir) {
  return path.join(scansDir, UPLOADS_SUBDIR, crypto.randomBytes(4).toString('hex'));
}

// Write uploaded files under destRoot preserving their tree; re-applies the
// ignore filter and rejects path traversal (defense-in-depth vs the client).
export function saveUploadedRepo(files, relPaths, destRoot) {
  const root = path.resolve(destRoot);
  fs.mkdirSync(root, { recursive: true });

  let saved = 0;
  let skipped = 0;
  let top = null;

  for (let i = 0; i < files.length; i++) {
    let rel = (relPaths[i] || files[i].originalname || '').replace(/\\/g, '/').replace(/^\/+/, '');
    if (!rel) { skipped++; continue; }

    const norm = path.posix.normalize(rel);
    if (norm === '..' || norm.startsWith('../') || path.posix.isAbsolute(norm)) { skipped++; continue; }
    if (isIgnored(norm)) { skipped++; continue; }

    const target = path.resolve(root, norm);
    if (target !== root && !target.startsWith(root + path.sep)) { skipped++; continue; }

    const segs = norm.split('/');
    if (segs.length > 1 && top === null) top = segs[0];

    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, files[i].buffer);
    saved++;
  }

  const repoRoot = top ? path.join(root, top) : root;
  return {
    repo_path: path.resolve(repoRoot),
    name: top || path.basename(root),
    file_count: saved,
    skipped,
  };
}
