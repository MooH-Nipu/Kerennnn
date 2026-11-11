const test = require('node:test');
const assert = require('node:assert/strict');
const { invokeJson } = require('./_internal-invoke');

test('captures status, json body and headers', async () => {
  const handler = async (req, res) => {
    assert.equal(req.authCurrent, true, 'auth must be injected');
    assert.equal(req.auth.userId, 'u1');
    res.setHeader('X-Test', 'yes');
    res.status(201).json({ ok: true, ioc: req.query.ioc });
  };
  const out = await invokeJson(handler, { query: { ioc: '8.8.8.8' }, auth: { userId: 'u1' } });
  assert.equal(out.status, 201);
  assert.deepEqual(out.body, { ok: true, ioc: '8.8.8.8' });
  assert.equal(out.headers['x-test'], 'yes');
});

test('parses stringified bodies and defaults to 200', async () => {
  const handler = async (_req, res) => { res.end(JSON.stringify({ ok: 1 })); };
  const out = await invokeJson(handler, {});
  assert.equal(out.status, 200);
  assert.deepEqual(out.body, { ok: 1 });
});
