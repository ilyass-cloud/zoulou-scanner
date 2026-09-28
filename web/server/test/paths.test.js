// Tests for the scan-target jail and upload filename handling.
//
// Uses the built-in node:test runner so the backend gains coverage without a
// new test dependency.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';

let resolveScanTarget;
let safeJoin;
let root;

before(async () => {
  // BROWSE_ROOT is read at call time by getBrowseRoot(), but set it before the
  // first import so nothing caches a different root.
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'jail-')));
  fs.mkdirSync(path.join(root, 'myrepo'), { recursive: true });
  process.env.BROWSE_ROOT = root;

  ({ resolveScanTarget, safeJoin } = await import('../lib/paths.js'));
});

after(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe('resolveScanTarget', () => {
  it('accepts a directory inside the browse root', () => {
    const result = resolveScanTarget(path.join(root, 'myrepo'));
    assert.equal(result.ok, true);
    assert.equal(result.path, path.join(root, 'myrepo'));
  });

  it('accepts the browse root itself', () => {
    assert.equal(resolveScanTarget(root).ok, true);
  });

  it('trims surrounding whitespace', () => {
    assert.equal(resolveScanTarget(`  ${root}  `).ok, true);
  });

  // The core of the fix: this path is bind-mounted into the runner container.
  for (const outside of ['/', '/etc', '/usr/bin']) {
    it(`rejects ${outside}, which is outside the root`, () => {
      const result = resolveScanTarget(outside);
      assert.equal(result.ok, false);
      assert.match(result.error, /outside the permitted roots/);
    });
  }

  it('rejects traversal that climbs out of the root', () => {
    assert.equal(resolveScanTarget(path.join(root, '..')).ok, false);
  });

  it('rejects a symlink inside the root that points outside it', () => {
    const link = path.join(root, 'escape');
    fs.symlinkSync('/etc', link);
    try {
      assert.equal(resolveScanTarget(link).ok, false);
    } finally {
      fs.unlinkSync(link);
    }
  });

  it('rejects a path that does not exist', () => {
    const result = resolveScanTarget(path.join(root, 'nope'));
    assert.equal(result.ok, false);
    assert.match(result.error, /does not exist/);
  });

  for (const empty of ['', '   ', null, undefined]) {
    it(`rejects ${JSON.stringify(empty)} as missing`, () => {
      const result = resolveScanTarget(empty);
      assert.equal(result.ok, false);
      assert.match(result.error, /required/);
    });
  }
});

describe('safeJoin', () => {
  const base = '/srv/uploads';

  it('joins an ordinary filename', () => {
    assert.equal(safeJoin(base, 'report.json'), path.join(base, 'report.json'));
  });

  it('joins a nested relative path', () => {
    assert.equal(safeJoin(base, 'a/b.txt'), path.join(base, 'a/b.txt'));
  });

  it('rejects traversal', () => {
    assert.equal(safeJoin(base, '../../etc/passwd'), null);
  });

  it('rejects backslash traversal from Windows clients', () => {
    assert.equal(safeJoin(base, '..\\..\\windows\\system32'), null);
  });

  it('confines an absolute name inside the root', () => {
    assert.equal(safeJoin(base, '/etc/passwd'), path.join(base, 'etc/passwd'));
  });

  it('rejects an empty name', () => {
    assert.equal(safeJoin(base, ''), null);
  });
});
