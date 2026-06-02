const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  makeSessionToken,
  verifySessionToken,
  buildSetCookie,
  buildClearCookie,
} = require('./_auth');

const SECRET = 'test-secret-123';

describe('session token', () => {
  test('sign → verify round-trip preserves payload', () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeSessionToken(
      { userId: 'u1', role: 'admin', username: 'alice', exp: now + 3600 },
      SECRET
    );
    const v = verifySessionToken(token, SECRET);
    assert.equal(v.ok, true);
    assert.equal(v.payload.userId, 'u1');
    assert.equal(v.payload.role, 'admin');
    assert.equal(v.payload.username, 'alice');
  });

  test('expired token is rejected', () => {
    const past = Math.floor(Date.now() / 1000) - 10;
    const token = makeSessionToken({ userId: 'u1', exp: past }, SECRET);
    const v = verifySessionToken(token, SECRET);
    assert.equal(v.ok, false);
    assert.equal(v.error, 'expired');
  });

  test('tampered signature is rejected', () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeSessionToken({ userId: 'u1', exp: now + 3600 }, SECRET);
    const last = token.slice(-1);
    const tampered = token.slice(0, -1) + (last === 'A' ? 'B' : 'A');
    assert.equal(verifySessionToken(tampered, SECRET).ok, false);
  });

  test('wrong secret is rejected', () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeSessionToken({ userId: 'u1', exp: now + 3600 }, SECRET);
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
});
