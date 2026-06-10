const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { collectRiskFactors, calcConfidenceWithFloors, cipSeverityToScore } = require('./correlate');

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

  test('Enrichment: freshly registered (<30d) yields a high new_registration factor', () => {
    const results = [{ source: 'Enrichment', meta: { 'Age (days)': 12 } }];
    const f = collectRiskFactors(results).find((x) => x.type === 'new_registration');
    assert.ok(f);
    assert.equal(f.severity, 'high');
    assert.equal(f.bonus, 10);
  });

  test('Enrichment: 30–89 day registration is a medium new_registration factor', () => {
    const results = [{ source: 'Enrichment', meta: { 'Age (days)': 60 } }];
    const f = collectRiskFactors(results).find((x) => x.type === 'new_registration');
    assert.ok(f);
    assert.equal(f.severity, 'med');
    assert.equal(f.bonus, 5);
  });

  test('Enrichment: aged registration (>=90d) yields no new_registration factor', () => {
    const results = [{ source: 'Enrichment', meta: { 'Age (days)': 4000 } }];
    assert.equal(collectRiskFactors(results).find((x) => x.type === 'new_registration'), undefined);
  });

  test('Enrichment: high-risk hosting org yields a hosting_provider factor', () => {
    const results = [{ source: 'Enrichment', meta: { Org: 'AS14061 DigitalOcean, LLC' } }];
    const f = collectRiskFactors(results).find((x) => x.type === 'hosting_provider');
    assert.ok(f);
    assert.equal(f.severity, 'med');
  });

  test('hosting_provider is deduped across AbuseIPDB + Enrichment (highest bonus kept)', () => {
    const results = [
      { source: 'AbuseIPDB', verdict: 'clean', meta: { 'Total Reports': 0, ISP: 'OVH SAS' } },
      { source: 'Enrichment', meta: { Org: 'OVH SAS' } },
    ];
    const hosting = collectRiskFactors(results).filter((x) => x.type === 'hosting_provider');
    assert.equal(hosting.length, 1);
    assert.equal(hosting[0].bonus, 10); // max of AbuseIPDB(10) / Enrichment(10)
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

  test('Abuse.ch group cap: three correlated sources all malicious + VT clean → baseline 50, not 67', () => {
    // Without cap: group weight 0.60 of total 0.90 → baseline 67.
    // With cap: group scaled to 0.30, total 0.60, maliciousSum 0.30 → baseline 50.
    const results = [
      { source: 'VirusTotal',    verdict: 'clean',    weight: 0.30 },
      { source: 'Abuse.ch',      verdict: 'malicious', weight: 0.20 },
      { source: 'ThreatFox',     verdict: 'malicious', weight: 0.15 },
      { source: 'MalwareBazaar', verdict: 'malicious', weight: 0.25 },
    ];
    const { baseline } = calcConfidenceWithFloors(results, []);
    assert.equal(baseline, 50);
  });

  test('two low-trust sources malicious among clean high-trust sources → floor 40, not 70', () => {
    // Old count-based formula: maliciousCount = 2 → floor 70.
    // New trust-weighted formula: maliciousWeight 0.22 < 0.50, ratio 25% < 60% → floor 40.
    const results = [
      { source: 'VirusTotal',   verdict: 'clean',    weight: 0.30 },
      { source: 'AlienVault OTX', verdict: 'clean',  weight: 0.15 },
      { source: 'AbuseIPDB',    verdict: 'clean',    weight: 0.20 },
      { source: 'Pulsedive',    verdict: 'malicious', weight: 0.10 },
      { source: 'Criminal IP',  verdict: 'malicious', weight: 0.12 },
    ];
    const { floor } = calcConfidenceWithFloors(results, []);
    assert.equal(floor, 40);
  });

  test('VT + GreyNoise both malicious → floor 70 via absolute weight arm', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.30 },
      { source: 'GreyNoise',  verdict: 'malicious', weight: 0.25, meta: {} },
    ];
    const { floor } = calcConfidenceWithFloors(results, []);
    assert.equal(floor, 70);
  });

  test('MalwareBazaar malicious match hard-floors confidence at >= 85', () => {
    const results = [
      { source: 'VirusTotal',    verdict: 'clean',    weight: 0.30 },
      { source: 'MalwareBazaar', verdict: 'malicious', weight: 0.25 },
    ];
    const { confidence } = calcConfidenceWithFloors(results, []);
    assert.ok(confidence >= 85);
  });

  test('GreyNoise malicious scanner hard-floors confidence at >= 65', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'clean',    weight: 0.30 },
      { source: 'GreyNoise',  verdict: 'malicious', weight: 0.25, meta: {} },
    ];
    const { confidence } = calcConfidenceWithFloors(results, []);
    assert.ok(confidence >= 65);
  });

  test('GreyNoise RIOT flag caps confidence at <= 15 regardless of other malicious sources', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.30 },
      { source: 'AbuseIPDB',  verdict: 'malicious', weight: 0.20 },
      { source: 'GreyNoise',  verdict: 'clean',     weight: 0.25, meta: { 'RIOT (trusted service)': 'yes' } },
    ];
    const { confidence } = calcConfidenceWithFloors(results, []);
    assert.ok(confidence <= 15);
  });
});

describe('cipSeverityToScore (Criminal IP severity strings)', () => {
  test('maps the 5 severity levels to a 0-100 score', () => {
    assert.equal(cipSeverityToScore('Safe'), 0);
    assert.equal(cipSeverityToScore('Low'), 15);
    assert.equal(cipSeverityToScore('Moderate'), 45);
    assert.equal(cipSeverityToScore('Dangerous'), 80);
    assert.equal(cipSeverityToScore('Critical'), 100);
  });

  test('is case-insensitive and trims whitespace', () => {
    assert.equal(cipSeverityToScore('  critical '), 100);
    assert.equal(cipSeverityToScore('DANGEROUS'), 80);
  });

  test('Critical/Dangerous map to malicious-range scores (>= 70)', () => {
    assert.ok(cipSeverityToScore('Critical') >= 70);
    assert.ok(cipSeverityToScore('Dangerous') >= 70);
  });

  test('Moderate maps to suspicious-range (>= 20, < 70)', () => {
    const s = cipSeverityToScore('Moderate');
    assert.ok(s >= 20 && s < 70);
  });

  test('passes through a numeric value and defaults unknown/empty to 0', () => {
    assert.equal(cipSeverityToScore(88), 88);
    assert.equal(cipSeverityToScore('nonsense'), 0);
    assert.equal(cipSeverityToScore(null), 0);
    assert.equal(cipSeverityToScore(undefined), 0);
  });
});
