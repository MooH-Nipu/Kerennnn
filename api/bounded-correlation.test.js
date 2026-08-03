const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('IOC workers await correlation before advancing queue', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/hooks/useVtScan.ts'), 'utf8');
  assert.match(source, /const corr = await api\.scan\.correlate\(ioc\)/);
  assert.doesNotMatch(source, /api\.scan\.correlate\(ioc\)\s*\.then/);
});

test('domain scans bypass cached correlation so URLScan always runs', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/hooks/useVtScan.ts'), 'utf8');
  assert.match(source, /if \(cachedCorr && type !== 'domain'\)/);
});