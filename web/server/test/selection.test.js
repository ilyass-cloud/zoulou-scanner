// Tests for the tool selection of a scan request (lib/selection.js).
//
// Regression: ticking the family switches without Auto-Scan used to plan zero
// tools, and the scan still ended « done » with an empty report.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { resolveToolSelection } from '../lib/selection.js';

const on = (...names) => Object.fromEntries(names.map((n) => [n, true]));

describe('resolveToolSelection', () => {
  it('turns ticked families into an automatic selection restricted to them', () => {
    const r = resolveToolSelection({}, on('sast', 'secrets'));
    assert.deepEqual(r, { ok: true, auto_scan: true, families: ['sast', 'secrets'] });
  });

  it('restricts Auto-Scan to the ticked families as well', () => {
    const r = resolveToolSelection({ auto_scan: true }, on('deps'));
    assert.deepEqual(r, { ok: true, auto_scan: true, families: ['deps'] });
  });

  it('keeps an explicit tool list as is, whatever the switches', () => {
    const r = resolveToolSelection({ selected_tools: ['bandit'] }, on('sast', 'deps'));
    assert.deepEqual(r, { ok: true, auto_scan: false });
  });

  it('lets Auto-Scan alone choose among all families', () => {
    assert.deepEqual(resolveToolSelection({ auto_scan: true }, {}), { ok: true, auto_scan: true });
  });

  it('accepts a network-only scan', () => {
    assert.deepEqual(resolveToolSelection({}, on('network')), { ok: true, auto_scan: false });
  });

  it('refuses a request that would run nothing, instead of an empty « done »', () => {
    const r = resolveToolSelection({}, {});
    assert.equal(r.ok, false);
    assert.match(r.error, /Aucun outil/);
  });
});
