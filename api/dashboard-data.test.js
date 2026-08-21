const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');

function loadHelper() {
  const file = path.resolve(__dirname, '../src/lib/dashboard-data.ts');
  const source = fs.readFileSync(file, 'utf8');
  const js = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText;
  const module = { exports: {} };
  vm.runInNewContext(js, { module, exports: module.exports });
  return module.exports.aggregateUserScans;
}

test('aggregateUserScans keeps top six and sums every remaining user into Other', () => {
  const aggregateUserScans = loadHelper();
  const rows = [3, 12, 8, 1, 9, 4, 7, 2].map((scans, i) => ({ username: `u${i}`, scans, uniqueIps: scans }));
  const snapshot = JSON.stringify(rows);

  const result = aggregateUserScans(rows);

  assert.deepEqual(Array.from(result, row => ({ ...row })), [
    { username: 'u1', scans: 12, uniqueIps: 12 },
    { username: 'u4', scans: 9, uniqueIps: 9 },
    { username: 'u2', scans: 8, uniqueIps: 8 },
    { username: 'u6', scans: 7, uniqueIps: 7 },
    { username: 'u5', scans: 4, uniqueIps: 4 },
    { username: 'u0', scans: 3, uniqueIps: 3 },
    { username: 'Other', scans: 3, uniqueIps: null },
  ]);
  assert.equal(JSON.stringify(rows), snapshot);
});

test('aggregateUserScans omits Other when six or fewer users exist', () => {
  const aggregateUserScans = loadHelper();
  const rows = [{ username: 'b', scans: 1, uniqueIps: 1 }, { username: 'a', scans: 2, uniqueIps: 2 }];
  assert.deepEqual(Array.from(aggregateUserScans(rows), row => ({ ...row })), [
    { username: 'a', scans: 2, uniqueIps: 2 },
    { username: 'b', scans: 1, uniqueIps: 1 },
  ]);
});
