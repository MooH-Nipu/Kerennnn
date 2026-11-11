const test = require('node:test');
const assert = require('node:assert/strict');
const { generateApiKey, hashApiKey, readApiKey, normalizeScopes, normalizeTypes } = require('./_apikeys');

test('generated keys are prefixed, unique, and hash to 64 hex chars', () => {
  const a = generateApiKey();
  const b = generateApiKey();
  assert.match(a.key, /^krn_[0-9a-f]{8}_[A-Za-z0-9_-]{32}$/);
  assert.ok(a.key.startsWith(a.prefix));
  assert.match(a.hash, /^[0-9a-f]{64}$/);
  assert.notEqual(a.key, b.key);
  assert.equal(a.hash, hashApiKey(a.key));
});

test('readApiKey accepts bearer and x-api-key, rejects garbage', () => {
  assert.equal(readApiKey({ headers: { authorization: 'Bearer krn_1_2' } }), 'krn_1_2');
  assert.equal(readApiKey({ headers: { authorization: 'bearer  krn_1_2 ' } }), 'krn_1_2');
  assert.equal(readApiKey({ headers: { 'x-api-key': 'krn_9_9' } }), 'krn_9_9');
  assert.equal(readApiKey({ headers: {} }), '');
  assert.equal(readApiKey({}), '');
});

test('scope and type normalizers keep known values only', () => {
  assert.deepEqual(normalizeScopes(['ioc:read', 'admin:everything']), ['ioc:read']);
  assert.deepEqual(normalizeScopes(['ioc:scan', 'ioc:read']), ['ioc:scan', 'ioc:read']);
  assert.deepEqual(normalizeScopes([]), ['ioc:scan']);
  assert.deepEqual(normalizeTypes(['domain']), ['domain']);
  assert.deepEqual(normalizeTypes(['ip', 'nope']), ['ip']);
  assert.deepEqual(normalizeTypes([]), ['ip', 'domain', 'hash']);
});
