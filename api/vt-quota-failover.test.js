const { describe, test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const envBackup = { ...process.env };
const httpPath = require.resolve('./_http');
const authPath = require.resolve('./_auth');
const vtKeysPath = require.resolve('./_vtkeys');
const vtPath = require.resolve('./vt');

function response() {
  return {
    headers: {},
    statusCode: null,
    body: null,
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    end() { return this; },
  };
}

function loadHandler(httpGet) {
  require.cache[httpPath] = { id: httpPath, filename: httpPath, loaded: true, exports: { httpGet } };
  const auth = require(authPath);
  require.cache[authPath].exports = { ...auth, requireAuth: () => true };
  delete require.cache[vtKeysPath];
  delete require.cache[vtPath];
  return require(vtPath);
}

function configureKeys(count = 6) {
  process.env.VT_API_KEY = 'key-1';
  for (const name of Object.keys(process.env)) {
    if (/^VT_API_KEY_\d+$/.test(name)) delete process.env[name];
  }
  for (let i = 2; i <= count; i++) process.env[`VT_API_KEY_${i}`] = `key-${i}`;
}

describe('VT quota failover contract', () => {
  beforeEach(() => configureKeys());

  afterEach(() => {
    process.env = { ...envBackup };
    delete require.cache[httpPath];
    delete require.cache[authPath];
    delete require.cache[vtKeysPath];
    delete require.cache[vtPath];
  });

  test('five exhausted keys do not prevent sixth key from serving request', async () => {
    let attempts = 0;
    const handler = loadHandler(async () => {
      attempts++;
      if (attempts < 6) return { status: 429, data: { error: { code: 'QuotaExceededError' } } };
      return { status: 200, data: { data: { attributes: {} } } };
    });
    const res = response();

    await handler({ method: 'GET', query: { ioc: 'example.com' } }, res);

    assert.equal(attempts, 6);
    assert.equal(res.statusCode, 200);
  });

  test('all exhausted keys disable short automatic retry', async () => {
    const handler = loadHandler(async () => ({
      status: 429,
      data: { error: { code: 'QuotaExceededError', message: 'Quota exceeded' } },
    }));
    const res = response();

    await handler({ method: 'GET', query: { ioc: 'example.com' } }, res);

    assert.equal(res.statusCode, 429);
    assert.equal(res.body.error.code, 'VT_QUOTA_EXHAUSTED');
    assert.equal(res.body.error.retryable, false);
    assert.equal(res.body.error.resetAt, undefined);
    assert.equal(res.headers['Retry-After'], undefined);
    assert.equal(res.body._debug.keyAttempts.length, 6);
  });

  test('exhausted plus invalid keys still disable automatic retry', async () => {
    let attempts = 0;
    const handler = loadHandler(async () => {
      attempts++;
      return attempts < 6
        ? { status: 429, data: { error: { code: 'QuotaExceededError' } } }
        : { status: 401, data: { error: { code: 'WrongCredentialsError' } } };
    });
    const res = response();

    await handler({ method: 'GET', query: { ioc: 'example.com' } }, res);

    assert.equal(res.statusCode, 429);
    assert.equal(res.body.error.code, 'VT_QUOTA_EXHAUSTED');
    assert.equal(res.body.error.retryable, false);
  });

  test('temporary throttling keeps bounded retry contract', async () => {
    const handler = loadHandler(async () => ({
      status: 429,
      data: { error: { code: 'TooManyRequestsError', message: 'Slow down' } },
    }));
    const res = response();

    await handler({ method: 'GET', query: { ioc: 'example.com' } }, res);

    assert.equal(res.statusCode, 429);
    assert.equal(res.body.error.code, 'VT_TEMPORARY_RATE_LIMIT');
    assert.equal(res.body.error.retryable, true);
    assert.equal(res.headers['Retry-After'], '60');
  });

  test('temporary plus invalid keys remains retryable', async () => {
    let attempts = 0;
    const handler = loadHandler(async () => {
      attempts++;
      return attempts < 6
        ? { status: 429, data: { error: { code: 'TooManyRequestsError' } } }
        : { status: 401, data: { error: { code: 'WrongCredentialsError' } } };
    });
    const res = response();

    await handler({ method: 'GET', query: { ioc: 'example.com' } }, res);

    assert.equal(res.statusCode, 429);
    assert.equal(res.body.error.code, 'VT_TEMPORARY_RATE_LIMIT');
    assert.equal(res.body.error.retryable, true);
    assert.equal(res.headers['Retry-After'], '60');
  });

  test('known cooling keys return locally without another VT call', async () => {
    let attempts = 0;
    const handler = loadHandler(async () => {
      attempts++;
      return { status: 429, data: { error: { code: 'TooManyRequestsError' } } };
    });

    await handler({ method: 'GET', query: { ioc: 'first.example' } }, response());
    assert.equal(attempts, 6);

    const res = response();
    await handler({ method: 'GET', query: { ioc: 'second.example' } }, res);

    assert.equal(attempts, 6);
    assert.equal(res.statusCode, 429);
    assert.equal(res.body.error.code, 'VT_TEMPORARY_RATE_LIMIT');
  });

  test('mixed exhausted and cooling keys remain temporarily retryable', async () => {
    configureKeys(2);
    const handler = loadHandler(async () => { throw new Error('VT should not be called'); });
    const keys = require('./_vtkeys');
    keys.markVtKeyQuotaExceeded('key-1', Date.now() + 60_000);
    keys.markVtKeyRateLimited('key-2', 60_000);
    const res = response();

    await handler({ method: 'GET', query: { ioc: 'mixed.example' } }, res);

    assert.equal(res.statusCode, 429);
    assert.equal(res.body.error.code, 'VT_TEMPORARY_RATE_LIMIT');
    assert.equal(res.body.error.retryable, true);
    assert.ok(Number(res.headers['Retry-After']) > 0);
  });
});
