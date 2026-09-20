const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const vt = require('./vt');

const NOW = Date.parse('2026-08-25T12:00:00.000Z');
const row = (verdict, hoursOld) => ({
  vt_verdict: verdict,
  last_scanned_at: new Date(NOW - hoursOld * 3_600_000).toISOString(),
  first_scanned_at: new Date(NOW - hoursOld * 3_600_000).toISOString(),
});

test('adaptive VT cache keeps risky evidence longer than clean evidence', () => {
  assert.equal(vt.cacheTtlHours('clean'), 1);
  assert.equal(vt.cacheTtlHours('unknown'), 1);
  assert.equal(vt.cacheTtlHours('suspicious'), 6);
  assert.equal(vt.cacheTtlHours('malicious'), 24);
});

test('cache freshness honors verdict-specific TTL boundaries', () => {
  assert.equal(vt.isFreshCacheRow(row('clean', 0.99), NOW), true);
  assert.equal(vt.isFreshCacheRow(row('clean', 1), NOW), false);
  assert.equal(vt.isFreshCacheRow(row('suspicious', 5.99), NOW), true);
  assert.equal(vt.isFreshCacheRow(row('suspicious', 6), NOW), false);
  assert.equal(vt.isFreshCacheRow(row('malicious', 23.99), NOW), true);
  assert.equal(vt.isFreshCacheRow(row('malicious', 24), NOW), false);
});

test('live refresh updates existing row, increments sightings, and invalidates old correlation', () => {
  const source = fs.readFileSync(path.resolve(__dirname, 'vt.js'), 'utf8');
  assert.match(source, /if \(existing\) \{[\s\S]*const nextScanCount = Number\(existing\.scan_count \|\| 0\) \+ 1;[\s\S]*\.update\(\{[\s\S]*scan_count: nextScanCount,[\s\S]*last_scanned_at: nowIso,[\s\S]*vt_verdict: vtVerdict,[\s\S]*corr_confidence: null,[\s\S]*corr_payload: \{\},[\s\S]*\.eq\('ip', ioc\)/);
});
