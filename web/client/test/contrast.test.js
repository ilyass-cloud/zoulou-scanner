// Colour-contrast regression guard (WCAG 1.4.3 Contrast Minimum, AA).
//
// This parses the real stylesheet rather than a copy of the values, so a future
// palette edit that drops a pair below 4.5:1 fails here. Ten of the twelve
// severity-badge combinations failed before this was checked; the dark theme
// was worse because it overrode the background without the text colour.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const CSS = fs.readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'index.css'),
  'utf-8'
);

const AA_NORMAL_TEXT = 4.5;

function channel(value) {
  const c = value / 255;
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

function luminance(hex) {
  const h = hex.replace('#', '');
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

export function contrast(fg, bg) {
  const [a, b] = [luminance(fg), luminance(bg)];
  const [hi, lo] = a > b ? [a, b] : [b, a];
  return (hi + 0.05) / (lo + 0.05);
}

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'];

/**
 * Pull the effective background/text pair for each severity out of the
 * stylesheet.
 *
 * Rules are walked in source order and merged, so a later rule overriding only
 * one property — exactly what the dark theme did, and the bug this guards —
 * still yields the pair that actually renders. Comma-separated selectors are
 * expanded, otherwise a shared rule silently covers only its last selector.
 */
function severityRules(darkTheme) {
  const effective = new Map();

  for (const [, selector, body] of CSS.matchAll(/([^{}]+)\{([^}]*)\}/g)) {
    const isDarkRule = selector.includes('[data-theme="dark"]');
    if (isDarkRule !== darkTheme) continue;

    const bg = body.match(/background:\s*(#[0-9a-fA-F]{6})/);
    const fg = body.match(/(?<!-)color:\s*(#[0-9a-fA-F]{6})/);
    if (!bg && !fg) continue;

    for (const name of SEVERITIES) {
      if (!new RegExp(`\\.sev-${name}\\b`).test(selector)) continue;
      const current = effective.get(name) || {};
      effective.set(name, {
        name,
        bg: bg ? bg[1] : current.bg,
        fg: fg ? fg[1] : current.fg,
      });
    }
  }

  // A dark rule may inherit its text colour from the light rule, so fill gaps
  // from the base theme before judging — that inheritance was the original bug.
  if (darkTheme) {
    const light = new Map(severityRules(false).map((r) => [r.name, r]));
    for (const [name, rule] of effective) {
      effective.set(name, {
        ...rule,
        fg: rule.fg ?? light.get(name)?.fg,
        bg: rule.bg ?? light.get(name)?.bg,
      });
    }
  }

  return [...effective.values()].filter((r) => r.fg && r.bg);
}

describe('contrast helper', () => {
  it('computes the known extremes', () => {
    assert.equal(Math.round(contrast('#000000', '#ffffff')), 21);
    assert.equal(Math.round(contrast('#ffffff', '#ffffff')), 1);
  });

  it('is symmetric', () => {
    assert.equal(contrast('#b91c1c', '#fee2e2'), contrast('#fee2e2', '#b91c1c'));
  });
});

describe('severity badges meet AA in the light theme', () => {
  const rules = severityRules(false);

  it('finds every severity rule in the stylesheet', () => {
    assert.equal(rules.length, 6, `expected all six severity levels, found ${rules.map((r) => r.name).join(", ")}`);
  });

  for (const { name, fg, bg } of rules) {
    it(`${name} (${fg} on ${bg})`, () => {
      const ratio = contrast(fg, bg);
      assert.ok(
        ratio >= AA_NORMAL_TEXT,
        `${name} is ${ratio.toFixed(2)}:1, below the ${AA_NORMAL_TEXT}:1 minimum`
      );
    });
  }
});

describe('severity badges meet AA in the dark theme', () => {
  const rules = severityRules(true);

  it('overrides the text colour, not just the background', () => {
    // The original bug: only `background` was overridden, so the light theme's
    // dark ink was left sitting on a dark background.
    assert.equal(rules.length, 6, `expected all six severity levels, found ${rules.map((r) => r.name).join(", ")}`);
  });

  for (const { name, fg, bg } of rules) {
    it(`${name} (${fg} on ${bg})`, () => {
      const ratio = contrast(fg, bg);
      assert.ok(
        ratio >= AA_NORMAL_TEXT,
        `${name} is ${ratio.toFixed(2)}:1, below the ${AA_NORMAL_TEXT}:1 minimum`
      );
    });
  }
});

describe('accent colour', () => {
  const accent = CSS.match(/--accent:\s*(#[0-9a-fA-F]{6})/)[1];

  it('is readable as body text on a light card', () => {
    const ratio = contrast(accent, '#ffffff');
    assert.ok(ratio >= AA_NORMAL_TEXT, `link colour is ${ratio.toFixed(2)}:1 on white`);
  });

  it('is readable behind white button text', () => {
    const ratio = contrast('#ffffff', accent);
    assert.ok(ratio >= AA_NORMAL_TEXT, `primary button is ${ratio.toFixed(2)}:1`);
  });
});
