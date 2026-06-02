const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { collectRiskFactors, calcConfidenceWithFloors } = require('./correlate');

describe('collectRiskFactors', () => {
  test('VT with 6 malicious yields a high-severity detection factor', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', meta: { Malicious: 6, 'Total Engines': 90 } },
    ];
    const vt = collectRiskFactors(results).find((f) => f.type === 'vt_detection');
    assert.ok(vt);
    assert.equal(vt.severity, 'high');
    assert.equal(vt.bonus, 10);
  });

  test('skipped / errored sources contribute no factors', () => {
    const results = [
      { source: 'VirusTotal', skipped: true },
      { source: 'AbuseIPDB', error: 'nope' },
    ];
    assert.equal(collectRiskFactors(results).length, 0);
  });

  test('AbuseIPDB with 30 reports yields a high many_reports factor', () => {
    const results = [
      {
        source: 'AbuseIPDB',
        verdict: 'malicious',
        meta: { 'Total Reports': 30, ISP: 'Example ISP', 'Usage Type': 'Commercial' },
      },
    ];
    const f = collectRiskFactors(results).find((x) => x.type === 'many_reports');
    assert.ok(f);
    assert.equal(f.severity, 'high');
    assert.equal(f.bonus, 15);
  });
});

describe('calcConfidenceWithFloors', () => {
  test('two malicious sources floor confidence at >= 70', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.25 },
      { source: 'AbuseIPDB', verdict: 'malicious', weight: 0.25 },
    ];
    const { floor, confidence } = calcConfidenceWithFloors(results, []);
    assert.equal(floor, 70);
    assert.ok(confidence >= 70);
  });

  test('all-clean sources → zero confidence, no floor', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'clean', weight: 0.25 },
      { source: 'AbuseIPDB', verdict: 'clean', weight: 0.25 },
    ];
    const { floor, confidence } = calcConfidenceWithFloors(results, []);
    assert.equal(floor, 0);
    assert.equal(confidence, 0);
  });

  test('no active sources → null confidence', () => {
    const { confidence } = calcConfidenceWithFloors([{ skipped: true }], []);
    assert.equal(confidence, null);
  });

  test('risk-factor bonus is capped at 25', () => {
    const results = [{ source: 'VirusTotal', verdict: 'suspicious', weight: 0.25 }];
    const { bonus } = calcConfidenceWithFloors(results, [{ bonus: 100 }]);
    assert.equal(bonus, 25);
  });
});
