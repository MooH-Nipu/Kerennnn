const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  makeSessionToken,
  verifySessionToken,
  buildSetCookie,
  buildClearCookie,
  validateCurrentIdentity,
  shouldRevalidateRoute,
  requireAuth,
} = require('./_auth');

const SECRET = 'test-secret-123';

describe('session token', () => {
  test('sign → verify round-trip preserves payload', () => {
    const token = makeSessionToken(
      { userId: 'u1', role: 'admin', username: 'alice' },
      SECRET,
      3600
    );
    const v = verifySessionToken(token, SECRET);
    assert.equal(v.ok, true);
    assert.equal(v.payload.userId, 'u1');
    assert.equal(v.payload.role, 'admin');
    assert.equal(v.payload.username, 'alice');
  });

  test('expired token is rejected', () => {
    const token = makeSessionToken({ userId: 'u1', iat: Math.floor(Date.now() / 1000) - 7200, exp: Math.floor(Date.now() / 1000) - 10 }, SECRET, 3600);
    const v = verifySessionToken(token, SECRET);
    assert.equal(v.ok, false);
    assert.equal(v.error, 'expired');
  });

  test('tampered signature is rejected', () => {
    const token = makeSessionToken({ userId: 'u1' }, SECRET, 3600);
    const last = token.slice(-1);
    const tampered = token.slice(0, -1) + (last === 'A' ? 'B' : 'A');
    assert.equal(verifySessionToken(tampered, SECRET).ok, false);
  });

  test('wrong secret is rejected', () => {
    const token = makeSessionToken({ userId: 'u1' }, SECRET, 3600);
    const v = verifySessionToken(token, 'other-secret');
    assert.equal(v.ok, false);
    assert.equal(v.error, 'bad_sig');
  });

  test('malformed tokens are rejected', () => {
    assert.equal(verifySessionToken('not-a-token', SECRET).ok, false);
    assert.equal(verifySessionToken('', SECRET).ok, false);
  });
});

describe('cookies', () => {
  test('buildSetCookie sets HttpOnly + SameSite + Max-Age', () => {
    const c = buildSetCookie('abc', { maxAge: 100, secure: false });
    assert.match(c, /soc_session=abc/);
    assert.match(c, /HttpOnly/);
    assert.match(c, /SameSite=Lax/);
    assert.match(c, /Max-Age=100/);
  });

  test('buildSetCookie adds Secure when requested', () => {
    assert.match(buildSetCookie('abc', { secure: true }), /Secure/);
  });

  test('buildClearCookie expires immediately', () => {
    assert.match(buildClearCookie(), /Max-Age=0/);
  });

  test('malformed percent-encoding is rejected as unauthorized without throwing', () => {
    const prior = process.env.APP_AUTH_SECRET;
    process.env.APP_AUTH_SECRET = SECRET;
    const response = {
      statusCode: 0,
      headers: {},
      setHeader(name, value) { this.headers[name] = value; },
      end(body) { this.body = body; },
    };
    try {
      assert.doesNotThrow(() => requireAuth({ headers: { cookie: 'soc_session=%' } }, response));
      assert.equal(response.statusCode, 401);
      assert.match(response.body, /Unauthorized/);
    } finally {
      if (prior === undefined) delete process.env.APP_AUTH_SECRET;
      else process.env.APP_AUTH_SECRET = prior;
    }
  });
});

describe('current database identity', () => {
  test('route boundary revalidates every protected API request', () => {
    assert.equal(shouldRevalidateRoute('/api/health'), false);
    assert.equal(shouldRevalidateRoute('/api/auth/login'), false);
    assert.equal(shouldRevalidateRoute('/api/auth/logout'), false);
    assert.equal(shouldRevalidateRoute('/api/vt'), true);
    assert.equal(shouldRevalidateRoute('/api/v1/team-filter'), true);
  });

  test('accepts only an existing user whose current role is allowed', () => {
    assert.deepEqual(
      validateCurrentIdentity(
        { userId: 'u1', role: 'soc_lead', username: 'old-name' },
        { id: 'u1', role: 'soc_lead', username: 'lead' },
        ['soc_lead', 'l2']
      ),
      { ok: true, auth: { userId: 'u1', role: 'soc_lead', username: 'lead' } }
    );
  });

  test('rejects deleted, demoted, or malformed identities', () => {
    assert.deepEqual(validateCurrentIdentity({ userId: 'u1', role: 'soc_lead' }, null, ['soc_lead']), { ok: false, status: 401 });
    assert.deepEqual(validateCurrentIdentity({ userId: 'u1', role: 'soc_lead' }, { id: 'u1', role: 'l1', username: 'lead' }, ['soc_lead']), { ok: false, status: 403 });
    assert.deepEqual(validateCurrentIdentity({}, { id: 'u1', role: 'soc_lead', username: 'lead' }, ['soc_lead']), { ok: false, status: 401 });
  });
});
