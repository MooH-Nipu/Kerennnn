const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

describe('getVtKeys', () => {
  const envBackup = { ...process.env };

  afterEach(() => {
    process.env = { ...envBackup };
  });

  test('dedupes and trims keys', () => {
    process.env.VT_API_KEY = '  key-a  ';
    process.env.VT_API_KEY_2 = 'key-b';
    process.env.VT_API_KEY_3 = 'key-a';
    process.env.VT_API_KEY_4 = '  key-b  ';
    delete process.env.VT_API_KEY_5;

    const { getVtKeys } = require('./_vtkeys');
    assert.deepEqual(getVtKeys(), ['key-a', 'key-b']);
  });
});

describe('getVtKeysForRequest', () => {
  const envBackup = { ...process.env };

  beforeEach(() => {
    delete require.cache[require.resolve('./_vtkeys')];
  });

  afterEach(() => {
    process.env = { ...envBackup };
    delete require.cache[require.resolve('./_vtkeys')];
  });

  test('rotates starting key across calls', () => {
    process.env.VT_API_KEY = 'k1';
    process.env.VT_API_KEY_2 = 'k2';
    process.env.VT_API_KEY_3 = 'k3';

    const { getVtKeysForRequest } = require('./_vtkeys');
    assert.deepEqual(getVtKeysForRequest(), ['k1', 'k2', 'k3']);
    assert.deepEqual(getVtKeysForRequest(), ['k2', 'k3', 'k1']);
    assert.deepEqual(getVtKeysForRequest(), ['k3', 'k1', 'k2']);
    assert.deepEqual(getVtKeysForRequest(), ['k1', 'k2', 'k3']);
  });
});

describe('isVtRateLimited', () => {
  const { isVtRateLimited } = require('./_vtkeys');

  test('429 and VT quota error codes', () => {
    assert.equal(isVtRateLimited(429, {}), true);
    assert.equal(isVtRateLimited(200, { error: { code: 'QuotaExceededError' } }), true);
    assert.equal(isVtRateLimited(200, { error: { code: 'TooManyRequestsError' } }), true);
  });

  test('403 ForbiddenError is not treated as rate limit', () => {
    assert.equal(
      isVtRateLimited(403, { error: { code: 'ForbiddenError', message: 'not allowed' } }),
      false
    );
  });

  test('404 NotFoundError is not rate limit', () => {
    assert.equal(
      isVtRateLimited(404, { error: { code: 'NotFoundError', message: 'not found' } }),
      false
    );
  });
});

describe('shouldTryNextVtKey', () => {
  const { shouldTryNextVtKey } = require('./_vtkeys');

  test('retries on bad credentials', () => {
    assert.equal(
      shouldTryNextVtKey(401, { error: { code: 'WrongCredentialsError' } }),
      true
    );
  });
});
