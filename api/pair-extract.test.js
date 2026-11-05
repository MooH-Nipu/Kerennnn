const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const load = () => import('../src/lib/pair-extract.mjs');
const src = f => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');

test('Kibana cell dump with IPs and API paths', async () => {
  const { extractPairs } = await load();
  const { rows, skipped } = extractPairs(
    '110.239.64.54\nRow: 1; Column: 1\n\n\n\n155,373\nRow: 1; Column: 2\n' +
    '/ib/rest/account/portfolioSummaryPost\nRow: 2; Column: 1\n2,067,930\nRow: 2; Column: 2\n' +
    'https://example.com/a?x=1\nRow: 3; Column: 1\n999\nRow: 3; Column: 2\n');
  assert.deepEqual(rows, [
    ['110.239.64.54', '155,373'],
    ['/ib/rest/account/portfolioSummaryPost', '2,067,930'],
    ['https://example.com/a?x=1', '999'],
  ]);
  assert.equal(skipped, 0);
});

test('one-pair-per-line formats: tab, spaces, comma, pipe, quoted csv', async () => {
  const { extractPairs, toTsv } = await load();
  const { rows } = extractPairs('1.1.1.1\t1,000\n2.2.2.2   20\n/a/b 3\n4.4.4.4,5\nfoo|6\n"7.7.7.7","8,000"');
  assert.equal(toTsv(rows), '1.1.1.1\t1,000\n2.2.2.2\t20\n/a/b\t3\n4.4.4.4\t5\nfoo\t6\n7.7.7.7\t8,000');
});

test('label without count is skipped and reported', async () => {
  const { extractPairs } = await load();
  const { rows, skipped } = extractPairs('orphan\nnext\n5');
  assert.deepEqual(rows, [['next', '5']]);
  assert.equal(skipped, 1);
});

test('Excel Converter tab is restricted to L2 and above', () => {
  assert.match(src('src/lib/permissions.ts'), /'pairs':\s+LEAD_ROLES/);
  assert.match(src('src/lib/permissions.ts'), /LEAD_ROLES: Role\[\] = \['admin', 'soc_lead', 'l2'\]/);
  assert.match(src('api/user-prefs.js'), /'pairs'/);
});
