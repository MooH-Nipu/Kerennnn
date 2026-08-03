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

test('URLScan always runs for domain IOCs (no opt-in required)', () => {
  const source = fs.readFileSync(path.join(__dirname, 'correlate.js'), 'utf8');
  // Should NOT check for active query param — URLScan is now automatic for domains
  assert.doesNotMatch(source, /req\.query\.active/);
  // Should still gate on type === 'domain'
  assert.match(source, /type === 'domain'/);
});

test('frontend no longer requires URLScan opt-in checkbox', () => {
  const page = fs.readFileSync(path.join(__dirname, '../src/pages/IocScanTab.tsx'), 'utf8');
  // Checkbox should be removed
  assert.doesNotMatch(page, /Active domain scan via URLScan/);
});