const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Each failed key attempt is a real outbound VT request. It must be logged
// before `continue`, otherwise the dashboard undercounts pool consumption.
test('failed VT key attempts are logged before failover continue', () => {
  const source = fs.readFileSync(path.join(__dirname, 'vt.js'), 'utf8');
  const block = source.slice(source.indexOf('if (shouldTryNextVtKey(status, data))'), source.indexOf("keyAttempts.push({ key: keyPrefix, status, result: 'ok' })"));
  assert.match(block, /logApiUsage\(req, \{[^}]*outcome: failOutcome/);
  assert.ok(block.indexOf('logApiUsage(') < block.lastIndexOf('continue;'));
});
