const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('provider-spending endpoints enforce per-user scan budgets', () => {
  for (const file of ['vt.js', 'correlate.js']) {
    const source = fs.readFileSync(path.join(__dirname, file), 'utf8');
    assert.match(source, /consumeScanBudget\(req, res, '(?:vt|correlate)'\)/);
  }
});

test('cache and health short-circuits happen before provider budget consumption', () => {
  const vt = fs.readFileSync(path.join(__dirname, 'vt.js'), 'utf8');
  const correlate = fs.readFileSync(path.join(__dirname, 'correlate.js'), 'utf8');
  assert.ok(vt.indexOf("req.query.health === '1'") < vt.indexOf("consumeScanBudget(req, res, 'vt')"));
  assert.ok(vt.indexOf('cached && cached.vt_payload') < vt.indexOf("consumeScanBudget(req, res, 'vt')"));
  assert.ok(correlate.indexOf('if (cachedCorr) return') < correlate.indexOf("consumeScanBudget(req, res, 'correlate')"));
});

test('URLScan active browsing requires explicit opt-in', () => {
  const source = fs.readFileSync(path.join(__dirname, 'correlate.js'), 'utf8');
  assert.match(source, /req\.query\.active === '1'/);
});

test('frontend exposes deliberate URLScan opt-in and forwards it only for domains', () => {
  const page = fs.readFileSync(path.join(__dirname, '../src/pages/IocScanTab.tsx'), 'utf8');
  const hook = fs.readFileSync(path.join(__dirname, '../src/hooks/useVtScan.ts'), 'utf8');
  assert.match(page, /Active domain scan via URLScan/);
  assert.match(hook, /type === 'domain' && opts\.activeDomainScan === true/);
});