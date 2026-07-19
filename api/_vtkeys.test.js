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

describe('VirusTotal limit classification', () => {
  const { isVtRateLimited, isVtTemporaryRateLimit, isVtQuotaExceeded } = require('./_vtkeys');

  test('distinguishes temporary throttling from exhausted quota', () => {
    assert.equal(isVtTemporaryRateLimit(429, { error: { code: 'TooManyRequestsError' } }), true);
    assert.equal(isVtTemporaryRateLimit(429, {}), true);
    assert.equal(isVtTemporaryRateLimit(429, { error: { code: 'QuotaExceededError' } }), false);
    assert.equal(isVtQuotaExceeded(429, { error: { code: 'QuotaExceededError' } }), true);
    assert.equal(isVtQuotaExceeded(200, { error: { code: 'QuotaExceededError' } }), true);
    assert.equal(isVtQuotaExceeded(429, { error: { code: 'TooManyRequestsError' } }), false);
    assert.equal(isVtRateLimited(429, { error: { code: 'QuotaExceededError' } }), true);
  });

  test('temporarily limited keys are excluded during cooldown', () => {
    process.env.VT_API_KEY = 'cooling-key';
    process.env.VT_API_KEY_2 = 'healthy-key';
    const { getVtKeysForRequest, markVtKeyRateLimited } = require('./_vtkeys');
    markVtKeyRateLimited('cooling-key', 60_000);
    assert.deepEqual(getVtKeysForRequest(), ['healthy-key']);
  });

  test('a single temporarily limited key is excluded during cooldown', () => {
    process.env.VT_API_KEY = 'only-key';
    delete process.env.VT_API_KEY_2;
    const { getVtKeysForRequest, markVtKeyRateLimited } = require('./_vtkeys');
    markVtKeyRateLimited('only-key', 60_000);
    assert.deepEqual(getVtKeysForRequest(), []);
  });

  test('quota-exhausted keys are excluded until reset', () => {
    process.env.VT_API_KEY = 'quota-key';
    process.env.VT_API_KEY_2 = 'healthy-key';
    const { getVtKeysForRequest, markVtKeyQuotaExceeded } = require('./_vtkeys');
    markVtKeyQuotaExceeded('quota-key', Date.now() + 60_000);
    assert.deepEqual(getVtKeysForRequest(), ['healthy-key']);
  });

  test('quota-exhausted keys support unknown reset time', () => {
    process.env.VT_API_KEY = 'unknown-reset-key';
    delete process.env.VT_API_KEY_2;
    const { getVtKeysForRequest, getVtKeyQuotaResetAt, isVtKeyQuotaExceeded, markVtKeyQuotaExceeded } = require('./_vtkeys');
    markVtKeyQuotaExceeded('unknown-reset-key');
    assert.equal(isVtKeyQuotaExceeded('unknown-reset-key'), true);
    assert.equal(getVtKeyQuotaResetAt('unknown-reset-key'), null);
    assert.deepEqual(getVtKeysForRequest(), []);
  });

  test('next cooldown ignores removed keys', () => {
    process.env.VT_API_KEY = 'current-key';
    delete process.env.VT_API_KEY_2;
    const { getNextVtCooldownAt, markVtKeyRateLimited } = require('./_vtkeys');
    markVtKeyRateLimited('removed-key', 60_000);
    assert.equal(getNextVtCooldownAt(), null);
  });

  test('quota-exhausted key becomes eligible after reset', () => {
    process.env.VT_API_KEY = 'quota-key';
    delete process.env.VT_API_KEY_2;
    const { getVtKeysForRequest, markVtKeyQuotaExceeded } = require('./_vtkeys');
    markVtKeyQuotaExceeded('quota-key', Date.now() - 1);
    assert.deepEqual(getVtKeysForRequest(), ['quota-key']);
  });

  test('quota state survives module reload when state file is configured', () => {
    const { mkdtempSync, rmSync } = require('node:fs');
    const { tmpdir } = require('node:os');
    const { join } = require('node:path');
    const dir = mkdtempSync(join(tmpdir(), 'vt-state-'));
    process.env.VT_API_KEY = 'persistent-key';
    delete process.env.VT_API_KEY_2;
    process.env.VT_KEY_STATE_FILE = join(dir, 'state.json');

    let keys = require('./_vtkeys');
    keys.markVtKeyQuotaExceeded('persistent-key', Date.now() + 60_000);
    delete require.cache[require.resolve('./_vtkeys')];
    keys = require('./_vtkeys');

    assert.deepEqual(keys.getVtKeysForRequest(), []);
    rmSync(dir, { recursive: true, force: true });
  });

  test('429 and VT quota error codes are rate limits', () => {
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
