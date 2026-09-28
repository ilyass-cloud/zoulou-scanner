// Tests for the /api authentication guard.
//
// The guard is deliberately conditional, so the cases that matter are both
// "does it block when enabled" and "does it stay out of the way when not".
import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { authRequired, requireAuth } from '../lib/auth.js';

const ENV_KEYS = ['REQUIRE_AUTH', 'DATABASE_URL'];
const saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
});

function setEnv({ requireAuthVar, databaseUrl }) {
  if (requireAuthVar === undefined) delete process.env.REQUIRE_AUTH;
  else process.env.REQUIRE_AUTH = requireAuthVar;
  if (databaseUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = databaseUrl;
}

// Minimal express req/res doubles: enough to observe the guard's decision.
function invoke(reqOverrides = {}) {
  const req = { path: '/tools', session: {}, ...reqOverrides };
  const result = { nextCalled: false, status: null, body: null };
  const res = {
    status(code) { result.status = code; return this; },
    json(payload) { result.body = payload; return this; },
  };
  requireAuth(req, res, () => { result.nextCalled = true; });
  return result;
}

describe('authRequired', () => {
  it('is off when neither variable is set, keeping the demo flow open', () => {
    setEnv({});
    assert.equal(authRequired(), false);
  });

  it('is on when a database is configured, since credentials can then exist', () => {
    setEnv({ databaseUrl: 'postgresql://localhost/db' });
    assert.equal(authRequired(), true);
  });

  for (const value of ['1', 'true', 'on', 'yes', 'TRUE']) {
    it(`is on when REQUIRE_AUTH=${value}`, () => {
      setEnv({ requireAuthVar: value });
      assert.equal(authRequired(), true);
    });
  }

  for (const value of ['0', 'false', 'off', 'no']) {
    it(`is off when REQUIRE_AUTH=${value}, overriding DATABASE_URL`, () => {
      setEnv({ requireAuthVar: value, databaseUrl: 'postgresql://localhost/db' });
      assert.equal(authRequired(), false);
    });
  }
});

describe('requireAuth', () => {
  it('lets everything through while auth is disabled', () => {
    setEnv({});
    assert.equal(invoke().nextCalled, true);
  });

  it('rejects an unauthenticated request when auth is enabled', () => {
    setEnv({ requireAuthVar: '1' });
    const result = invoke();
    assert.equal(result.nextCalled, false);
    assert.equal(result.status, 401);
  });

  // The route that made this a code-execution path rather than a missing feature.
  it('rejects unauthenticated writes to the tools registry', () => {
    setEnv({ requireAuthVar: '1' });
    assert.equal(invoke({ path: '/tools/add' }).status, 401);
  });

  it('rejects unauthenticated scan starts', () => {
    setEnv({ requireAuthVar: '1' });
    assert.equal(invoke({ path: '/scan' }).status, 401);
  });

  it('allows a request carrying a session', () => {
    setEnv({ requireAuthVar: '1' });
    assert.equal(invoke({ session: { user_id: 7 } }).nextCalled, true);
  });

  it('tolerates a missing session object', () => {
    setEnv({ requireAuthVar: '1' });
    assert.equal(invoke({ session: undefined }).status, 401);
  });

  // Without these there would be no way to log in, or to tell that a login is needed.
  for (const publicPath of ['/auth/login', '/auth/logout', '/auth/me', '/auth/status']) {
    it(`leaves ${publicPath} reachable while logged out`, () => {
      setEnv({ requireAuthVar: '1' });
      assert.equal(invoke({ path: publicPath }).nextCalled, true);
    });
  }

  it('does not treat a lookalike path as public', () => {
    setEnv({ requireAuthVar: '1' });
    assert.equal(invoke({ path: '/auth/login/../tools' }).status, 401);
  });
});
