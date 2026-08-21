const test = require('node:test');
const assert = require('node:assert/strict');
const { firstQueryError } = require('./recent-query-errors');

test('Dashboard aggregate counts fail closed on any query error', () => {
  const errors = [
    null,
    { error: { message: 'total failed' } },
    { error: { message: 'malicious failed' } },
    { error: { message: 'suspicious failed' } },
    { error: { message: 'clean failed' } },
  ];
  assert.equal(firstQueryError([{ count: 1 }, { count: 2 }]), null);
  for (const failed of errors.slice(1)) {
    assert.equal(firstQueryError([{ count: 1 }, failed, { count: 2 }]), failed.error);
  }
});
