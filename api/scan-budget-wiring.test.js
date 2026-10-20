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
  // Plugin architecture: URLScan plugin declares domain support in supportedTypes
  const { URLScanPlugin } = require('./plugins/urlscan');
  const plugin = new URLScanPlugin();
  assert.ok(plugin.supportedTypes.includes('domain'), 'URLScan.io plugin should declare domain support');
  assert.ok(!plugin.supportedTypes.includes('ip'), 'URLScan.io plugin should not support IP');
});

test('frontend no longer requires URLScan opt-in checkbox', () => {
  const page = fs.readFileSync(path.join(__dirname, '../src/pages/IocScanTab.tsx'), 'utf8');
  // Checkbox should be removed
  assert.doesNotMatch(page, /Active domain scan via URLScan/);
});

test('correlation cache is persisted server-side, never accepted from client', () => {
  const correlate = fs.readFileSync(path.join(__dirname, 'correlate.js'), 'utf8');
  const hook = fs.readFileSync(path.join(__dirname, '../src/hooks/useVtScan.ts'), 'utf8');
  const server = fs.readFileSync(path.join(__dirname, '../server.js'), 'utf8');

  assert.match(correlate, /corr_payload: responsePayload/);
  assert.doesNotMatch(hook, /saveCorrelation/);
  assert.doesNotMatch(server, /ip-cache\/correlation/);
});