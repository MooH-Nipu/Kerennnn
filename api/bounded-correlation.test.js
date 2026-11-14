const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = file => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');

test('IOC workers await correlation before advancing queue', () => {
  const hook = source('src/hooks/useVtScan.ts');
  assert.match(hook, /const corr = await api\.scan\.correlate\(ioc\)/);
  assert.doesNotMatch(hook, /api\.scan\.correlate\(ioc\)\s*\.then/);
});

test('correlation cache short-circuits every IOC type, with an explicit refresh opt-out', () => {
  const correlate = source('api/correlate.js');

  // The stored correlation is read for IP (vt_ip_cache) and non-IP (vt_ioc_cache).
  assert.match(correlate, /\.from\(type === 'ip' \? 'vt_ip_cache' : 'vt_ioc_cache'\)/);
  assert.match(correlate, /const cachedCorr = await corrFromCache\(ioc, type\)/);

  // No per-type gate: a repeat scan of any IOC type must not re-run every source.
  // (`type === 'ip'` may still appear for table selection and VT reuse, so the
  // guard is written against the retired cache gate itself.)
  assert.doesNotMatch(correlate, /if \(type === 'ip'\) \{\s*const cachedCorr/);

  // Analysts can still force a live scan; URLScan active evidence on demand.
  assert.match(correlate, /const refresh = String\(req\.query\?\.refresh \?\? ''\) === '1'/);
  assert.match(correlate, /p\.check\(ioc, type, \{ refresh \}\)/);
});

test('VT and correlation run as independent queues', () => {
  const hook = source('src/hooks/useVtScan.ts');

  // Separate workers with separate cursors: a slow VT queue cannot serialise
  // behind, or in front of, correlation.
  assert.match(hook, /async function vtWorker\(\)/);
  assert.match(hook, /async function corrWorker\(\)/);
  assert.match(hook, /let corrIdx = 0;/);
  assert.match(hook, /length: VT_CONCURRENCY \}, \(\) => vtWorker\(\)/);
  assert.match(hook, /length: CORR_CONCURRENCY \}, \(\) => corrWorker\(\)/);

  // Every row is declared before either queue starts, so out-of-order
  // resolution still finds its item.
  assert.match(hook, /const ids = parsed\.map/);
  assert.match(hook, /dispatch\(\{ type: 'ADD_PENDING', id: ids\[i\]/);
});
