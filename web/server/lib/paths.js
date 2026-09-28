// Path validation for anything the client can point the scanner at.
//
// Two separate holes motivated this module:
//
//   * /api/scan accepted any repo_path that merely existed, and jobManager
//     bind-mounts it into the runner container — so repo_path=/ handed the
//     whole host filesystem to the scan.
//   * repo_path is also substituted into scanner command templates, which used
//     to run under a shell, making it a command-injection vector too.
//
// lib/browse.js already jails directory *browsing* to a root; the scan side
// simply never applied the same rule. These helpers apply it consistently.
import fs from 'node:fs';
import path from 'node:path';

import { config, UPLOADS_SUBDIR } from '../config.js';
import { getBrowseRoot, within } from './browse.js';

/**
 * Roots a scan target may live under:
 *   - the browse root, i.e. what the picker is allowed to show, and
 *   - the uploads dir, where uploaded folders and git clones land.
 */
export function scanRoots() {
  const scansDir = path.resolve(config.projectRoot, config.scansDir);
  return [getBrowseRoot(), path.join(scansDir, UPLOADS_SUBDIR)];
}

/**
 * Resolve a client-supplied scan target, following symlinks so a link inside an
 * allowed root cannot point out of it.
 *
 * @returns {{ ok: true, path: string } | { ok: false, error: string }}
 */
export function resolveScanTarget(input) {
  const raw = String(input ?? '').trim();
  if (!raw) return { ok: false, error: 'repo_path is required' };

  let resolved;
  try {
    // realpath collapses '..' and resolves symlinks; it throws if absent.
    resolved = fs.realpathSync(path.resolve(raw));
  } catch {
    return { ok: false, error: `repo_path does not exist: ${raw}` };
  }

  const roots = scanRoots();
  if (!roots.some((root) => within(resolved, root))) {
    return {
      ok: false,
      error:
        `repo_path is outside the permitted roots (${roots.join(', ')}). ` +
        'Set BROWSE_ROOT or WORKSPACE_DIR to the directory holding the repositories you scan.',
    };
  }

  return { ok: true, path: resolved };
}

/**
 * Join an untrusted filename onto a directory without letting it escape.
 *
 * Mirrors the normalize-then-verify-prefix check in lib/ignore.js. Uploaded
 * filenames arrive straight from the browser and may contain path separators.
 *
 * @returns {string|null} the safe absolute path, or null if the name escapes.
 */
export function safeJoin(dir, name) {
  const root = path.resolve(dir);
  const rel = String(name ?? '').replace(/\\/g, '/').replace(/^\/+/, '');
  if (!rel) return null;

  const norm = path.posix.normalize(rel);
  if (norm === '..' || norm.startsWith('../') || path.posix.isAbsolute(norm)) return null;

  const target = path.resolve(root, norm);
  return within(target, root) ? target : null;
}
