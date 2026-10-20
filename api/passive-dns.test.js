const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const httpPath = require.resolve('./_http');
const authPath = require.resolve('./_auth');
const usagePath = require.resolve('./_usage');
const handlerPath = require.resolve('./passive-dns');

async function lookup(text, status = 200, ioc = 'example.com') {
  const saved = [httpPath, authPath, usagePath, handlerPath].map(path => [path, require.cache[path]]);
  const outcomes = [];
  try {
    require.cache[httpPath] = { id: httpPath, filename: httpPath, loaded: true, exports: { httpGetText: async () => ({ status, text }) } };
    require.cache[authPath] = { id: authPath, filename: authPath, loaded: true, exports: { requireAuth: () => true } };
    require.cache[usagePath] = { id: usagePath, filename: usagePath, loaded: true, exports: { logApiUsage: async (_, row) => { outcomes.push(row.outcome); } } };
    delete require.cache[handlerPath];
    const handler = require(handlerPath);
    const res = { statusCode: 200, setHeader() {}, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
    await handler({ method: 'GET', query: { ioc } }, res);
    await Promise.resolve();
    return { status: res.statusCode, body: res.body, outcomes };
  } finally {
    for (const [path, entry] of saved) {
      if (entry) require.cache[path] = entry;
      else delete require.cache[path];
    }
  }
}

test('HackerTarget plain-text quota response is not empty DNS evidence', async () => {
  const res = await lookup('API count exceeded - Increase Quota with Membership');
  assert.equal(res.status, 429);
  assert.match(res.body.error, /quota/i);
  assert.equal(res.body.records, undefined);
  assert.deepEqual(res.outcomes, ['rate_limited']);
});

test('HackerTarget errors are not empty DNS evidence', async () => {
  for (const message of ['error check input', 'invalid query', 'not found', '']) {
    const res = await lookup(message);
    assert.equal(res.status, 502, message);
    assert.equal(res.body.records, undefined);
    assert.deepEqual(res.outcomes, ['error']);
  }
});

test('valid no-record and populated DNS responses remain distinct', async () => {
  const empty = await lookup('No records found');
  assert.equal(empty.status, 200);
  assert.deepEqual(empty.body.records, []);
  assert.deepEqual(empty.outcomes, ['ok']);
  const populated = await lookup('host.example.com,1.2.3.4');
  assert.deepEqual(populated.body.records, [{ host: 'host.example.com', ip: '1.2.3.4' }]);
});

test('relationship UI does not turn failed candidate lookups into verified no-edges', () => {
  const ui = readFileSync(join(__dirname, '../src/components/vt/PassiveDnsPanel.tsx'), 'utf8');
  assert.match(ui, /settled\.find\(result => result\.status === 'rejected'\)/);
  assert.match(ui, /failed\.reason instanceof Error \? failed\.reason\.message/);
  assert.match(ui, /setRelationError\(/);
  assert.match(ui, /relations && !relationLoading && !relationError/);
});
