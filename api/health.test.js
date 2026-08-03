'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const handler = require('./health');

function response() {
  return {
    statusCode: null,
    body: null,
    headers: {},
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    end() { return this; },
  };
}

test('public health response exposes only service availability', async () => {
  process.env.VT_API_KEY = 'secret-provider-key';
  process.env.NODE_ENV = 'production';
  const res = response();

  await handler({ method: 'GET' }, res);

  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body, { ok: true });
  assert.equal(res.headers['cache-control'], 'no-store');
});

test('public health rejects unsupported methods', async () => {
  const res = response();

  await handler({ method: 'POST' }, res);

  assert.equal(res.statusCode, 405);
  assert.deepEqual(res.body, { error: 'Method not allowed.' });
});
