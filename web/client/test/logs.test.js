// Tests for the live-log batching and retention rules.
//
// These decide whether a verbose scan stays usable. The previous ScanLive
// called setLogs once per SSE line with `[...cur, line]` and re-mapped the
// whole array each render — quadratic, ~12.5M element renders for 5000 lines.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { appendCapped, applyPluginProgress, lineClass, MAX_LOG_LINES, TOOL_FAMILY } from '../src/lib/logs.js';

const entry = (text) => ({ id: 0, text, cls: lineClass(text) });

describe('lineClass', () => {
  for (const [line, expected] of [
    ['[ERROR] boom', 'log-line-error'],
    ['[CRITICAL] boom', 'log-line-error'],
    ['[WARNING] hmm', 'log-line-warn'],
    ['[WARN] hmm', 'log-line-warn'],
    ['[INFO] fine', 'log-line-info'],
    ['[DEBUG] noisy', 'log-line-debug'],
    ['plain text', ''],
  ]) {
    it(`classifies ${JSON.stringify(line)}`, () => {
      assert.equal(lineClass(line), expected);
    });
  }

  it('prefers the more severe classification', () => {
    assert.equal(lineClass('[INFO] saw an [ERROR] earlier'), 'log-line-error');
  });
});

describe('appendCapped', () => {
  it('appends a batch', () => {
    assert.deepEqual(appendCapped(['a'], ['b', 'c'], 10), ['a', 'b', 'c']);
  });

  it('returns the original array for an empty batch so React can bail out', () => {
    const existing = ['a'];
    assert.equal(appendCapped(existing, [], 10), existing);
  });

  it('keeps the newest lines when the cap is exceeded', () => {
    assert.deepEqual(appendCapped(['a', 'b', 'c'], ['d'], 3), ['b', 'c', 'd']);
  });

  it('caps a single oversized batch', () => {
    const batch = Array.from({ length: 50 }, (_, i) => i);
    assert.deepEqual(appendCapped([], batch, 5), [45, 46, 47, 48, 49]);
  });

  it('holds at the cap across many batches', () => {
    let logs = [];
    for (let i = 0; i < 10000; i++) logs = appendCapped(logs, [i], 100);
    assert.equal(logs.length, 100);
    assert.equal(logs.at(-1), 9999);
  });

  it('defaults to MAX_LOG_LINES', () => {
    const batch = Array.from({ length: MAX_LOG_LINES + 500 }, (_, i) => i);
    assert.equal(appendCapped([], batch).length, MAX_LOG_LINES);
  });
});

describe('applyPluginProgress', () => {
  const initial = Object.freeze({ sast: 'waiting', deps: 'waiting' });

  it('returns the same object when nothing matched, so no re-render happens', () => {
    assert.equal(applyPluginProgress(initial, [entry('nothing of interest')]), initial);
  });

  it('marks a plugin running', () => {
    const next = applyPluginProgress(initial, [entry("runner: starting plugin 'sast'")]);
    assert.equal(next.sast, 'running');
    assert.equal(next.deps, 'waiting');
  });

  it('marks a plugin done on an OK finish', () => {
    const next = applyPluginProgress(initial, [
      entry("runner: plugin 'sast' finished in 1.20s – OK"),
    ]);
    assert.equal(next.sast, 'done');
  });

  it('marks a plugin errored on a failed finish', () => {
    const next = applyPluginProgress(initial, [
      entry("runner: plugin 'deps' finished in 0.30s – FAILED (exit=127)"),
    ]);
    assert.equal(next.deps, 'error');
  });

  it('folds a whole batch in one pass', () => {
    const next = applyPluginProgress(initial, [
      entry("runner: starting plugin 'sast'"),
      entry('some noise'),
      entry("runner: plugin 'sast' finished in 1.20s – OK"),
      entry("runner: starting plugin 'deps'"),
    ]);
    assert.equal(next.sast, 'done');
    assert.equal(next.deps, 'running');
  });

  it('does not mutate the object it was given', () => {
    const before = { ...initial };
    applyPluginProgress(initial, [entry("runner: starting plugin 'sast'")]);
    assert.deepEqual(initial, before);
  });

  it('copies at most once per batch', () => {
    const next = applyPluginProgress(initial, [
      entry("runner: starting plugin 'sast'"),
      entry("runner: starting plugin 'deps'"),
    ]);
    assert.equal(next.sast, 'running');
    assert.equal(next.deps, 'running');
  });
});

// Lines copied from a real containerised scan (run 0ba704a4). The runner logs
// per tool, not per family, and the cards used to stay on « waiting » throughout.
describe('applyPluginProgress — containerised runner', () => {
  const W = Object.freeze({ sast: 'waiting', deps: 'waiting', secrets: 'waiting', container: 'waiting', network: 'waiting' });
  const L = {
    semgrepStart: '23:28:13 [INFO] orchestrator.plugins.live_plugin: live_plugin[semgrep]: executing: semgrep --sarif -o /app/scans/0ba704a4/raw/semgrep/semgrep_output.sarif.json /scan/target',
    semgrepEnd: '23:28:49 [INFO] orchestrator.plugins.live_plugin: live_plugin[semgrep]: finished in 35.28s (exit=0)',
    banditStart: '23:28:50 [INFO] orchestrator.plugins.live_plugin: live_plugin[bandit]: executing: bandit -r /scan/target -f json -o /app/scans/0ba704a4/raw/bandit/bandit_output.json',
    banditEnd: '23:28:51 [INFO] orchestrator.plugins.live_plugin: live_plugin[bandit]: finished in 0.62s (exit=1)',
    gitleaksStart: '23:28:51 [INFO] orchestrator.plugins.live_plugin: live_plugin[gitleaks]: executing: gitleaks detect --source /scan/target --no-git',
    complete: '23:28:53 [INFO] orchestrator.run_plan: === Runner complete: 3 artifact(s), 1 non-zero exit(s) ===',
  };

  it('maps a tool to its family when it starts', () => {
    assert.equal(applyPluginProgress(W, [entry(L.semgrepStart)]).sast, 'running');
  });

  it('marks the family done when the tool finishes, even with findings (exit=1)', () => {
    const next = applyPluginProgress(W, [L.banditStart, L.banditEnd].map(entry));
    assert.equal(next.sast, 'done');
  });

  it('follows a whole scan, and closes what is left at « Runner complete »', () => {
    const seq = [L.semgrepStart, L.semgrepEnd, L.banditStart, L.banditEnd, L.gitleaksStart].map(entry);
    const mid = applyPluginProgress(W, seq);
    assert.deepEqual([mid.sast, mid.secrets, mid.deps], ['done', 'running', 'waiting']);
    const end = applyPluginProgress(mid, [entry(L.complete)]);
    assert.deepEqual([end.sast, end.secrets, end.deps], ['done', 'done', 'waiting']);
  });

  it('keeps a failure visible after a sibling tool succeeds', () => {
    const seq = ['live_plugin[semgrep]: FAILED – timed out after 600s', L.banditStart, L.banditEnd].map(entry);
    assert.equal(applyPluginProgress(W, seq).sast, 'error');
  });

  it('knows every tool of the registry', () => {
    for (const t of ['semgrep', 'bandit', 'pip-audit', 'npm-audit', 'safety', 'gitleaks', 'trufflehog', 'trivy', 'grype', 'nmap']) {
      assert.ok(TOOL_FAMILY[t], t);
    }
  });
});
