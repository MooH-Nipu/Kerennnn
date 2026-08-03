const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  collectRiskFactors, calcConfidenceWithFloors,
  checkWarningList, corroborationBonus, bayesianConfidence,
  enrichmentMultiplier, decayMultiplier, sightingBoost,
  applyTypeWeights, calculateOptimizedConfidence, parseMalwareBazaar,
} = require('./correlate');


describe('MalwareBazaar hash lookup', () => {
  test('known hash becomes malicious with useful metadata', () => {
    const result = parseMalwareBazaar({
      query_status: 'ok',
      data: [{
        sha256_hash: 'abc123',
        file_name: 'payload.exe',
        file_type: 'exe',
        signature: 'CobaltStrike',
        first_seen: '2026-07-01 00:00:00',
        tags: ['c2', 'loader'],
      }],
    }, 'abc123');

    assert.equal(result.source, 'MalwareBazaar');
    assert.equal(result.verdict, 'malicious');
    assert.equal(result.score, 100);
    assert.equal(result.meta.Signature, 'CobaltStrike');
    assert.match(result.link, /abc123/);
  });

  test('unknown hash becomes clean', () => {
    const result = parseMalwareBazaar({ query_status: 'hash_not_found' }, 'deadbeef');
    assert.equal(result.verdict, 'clean');
    assert.equal(result.score, 0);
  });
});

const { isCompleteCorrelationPayload } = require('./_correlation-cache');

// ── Legacy tests (unchanged) ─────────────────────────────────────────────

describe('cached correlation completeness', () => {
  test('incomplete source errors force next scan to retry threat intel', () => {
    const payload = { sources: [
      { source: 'VirusTotal', verdict: 'clean' },
      { source: 'AbuseIPDB', error: 'timeout' },
    ] };
    assert.equal(isCompleteCorrelationPayload(payload), false);
  });

  test('correlation with successful sources can be reused', () => {
    const payload = { sources: [
      { source: 'VirusTotal', verdict: 'clean' },
      { source: 'AbuseIPDB', verdict: 'clean' },
    ] };
    assert.equal(isCompleteCorrelationPayload(payload), true);
  });
});

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
    assert.equal(hosting[0].bonus, 10);
  });
});

describe('calcConfidenceWithFloors (legacy)', () => {
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

  test('moderate malicious weight (0.20–0.50) floors confidence at 40, not 70', () => {
    const results = [
      { source: 'VirusTotal',     verdict: 'clean',     weight: 0.30 },
      { source: 'AbuseIPDB',      verdict: 'malicious', weight: 0.20 },
      { source: 'AlienVault OTX', verdict: 'malicious', weight: 0.15 },
    ];
    const { floor } = calcConfidenceWithFloors(results, []);
    assert.equal(floor, 40);
  });
});

// ── Scoring v2 tests ─────────────────────────────────────────────────────

describe('checkWarningList', () => {
  test('DNS resolver IP is listed', () => {
    const r = checkWarningList('8.8.8.8', {});
    assert.equal(r.listed, true);
    assert.equal(r.reason, 'dns_resolver');
  });

  test('Cloudflare CDN via enrichment Org is listed', () => {
    const r = checkWarningList('1.2.3.4', { Org: 'AS13335 Cloudflare, Inc.' });
    assert.equal(r.listed, true);
    assert.equal(r.reason, 'cdn');
    assert.equal(r.match, 'cloudflare');
  });

  test('Akamai CDN via ISP is listed', () => {
    const r = checkWarningList('5.6.7.8', { ISP: 'Akamai Technologies' });
    assert.equal(r.listed, true);
    assert.equal(r.match, 'akamai');
  });

  test('normal IP is not listed', () => {
    const r = checkWarningList('203.0.113.50', { Org: 'Example Corp' });
    assert.equal(r.listed, false);
  });

  test('null enrichment meta — not listed', () => {
    const r = checkWarningList('198.51.100.1', null);
    assert.equal(r.listed, false);
  });

  test('empty enrichment — not listed', () => {
    const r = checkWarningList('198.51.100.1', {});
    assert.equal(r.listed, false);
  });
});

describe('corroborationBonus', () => {
  test('2 malicious sources → +10', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.25 },
      { source: 'AbuseIPDB', verdict: 'malicious', weight: 0.30 },
    ];
    assert.equal(corroborationBonus(results), 10);
  });

  test('3 malicious sources → +15 (+5 diversity = 20 total)', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.25 },
      { source: 'AbuseIPDB', verdict: 'malicious', weight: 0.30 },
      { source: 'Abuse.ch', verdict: 'malicious', weight: 0.15 },
    ];
    assert.equal(corroborationBonus(results), 20); // 15 consensus + 5 diversity = 20
  });

  test('3 malicious from diverse sources → +15 +5 = +20 (capped)', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.25 },
      { source: 'AbuseIPDB', verdict: 'malicious', weight: 0.30 },
      { source: 'AlienVault OTX', verdict: 'malicious', weight: 0.10 },
    ];
    assert.equal(corroborationBonus(results), 20); // 15 + 5 = 20, capped at 20
  });

  test('1 malicious + 1 clean → no bonus', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.25 },
      { source: 'AbuseIPDB', verdict: 'clean', weight: 0.30 },
    ];
    assert.equal(corroborationBonus(results), 0);
  });

  test('3 suspicious only → +5', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'suspicious', weight: 0.25 },
      { source: 'AbuseIPDB', verdict: 'suspicious', weight: 0.30 },
      { source: 'Abuse.ch', verdict: 'suspicious', weight: 0.15 },
    ];
    assert.equal(corroborationBonus(results), 5);
  });

  test('skipped/errored sources are ignored', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.25 },
      { source: 'AbuseIPDB', skipped: true },
      { source: 'Abuse.ch', error: 'timeout' },
    ];
    assert.equal(corroborationBonus(results), 0);
  });

  test('empty results → 0', () => {
    assert.equal(corroborationBonus([]), 0);
  });
});

describe('bayesianConfidence', () => {
  test('all clean → low confidence (near 0)', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'clean', weight: 0.25, skipped: false },
      { source: 'AbuseIPDB', verdict: 'clean', weight: 0.30, skipped: false },
    ];
    const score = bayesianConfidence(results);
    assert.ok(score !== null);
    assert.ok(score < 10, `expected < 10, got ${score}`);
  });

  test('all malicious → high confidence (>70)', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.25, skipped: false },
      { source: 'AbuseIPDB', verdict: 'malicious', weight: 0.30, skipped: false },
      { source: 'Abuse.ch', verdict: 'malicious', weight: 0.15, skipped: false },
    ];
    const score = bayesianConfidence(results);
    assert.ok(score !== null);
    assert.ok(score > 70, `expected > 70, got ${score}`);
  });

  test('mixed verdicts → moderate confidence', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.25, skipped: false },
      { source: 'AbuseIPDB', verdict: 'clean', weight: 0.30, skipped: false },
      { source: 'Abuse.ch', verdict: 'suspicious', weight: 0.15, skipped: false },
    ];
    const score = bayesianConfidence(results);
    assert.ok(score !== null);
    assert.ok(score >= 10 && score <= 50, `expected 10-50, got ${score}`);
  });

  test('no active sources → null', () => {
    assert.equal(bayesianConfidence([{ skipped: true }]), null);
    assert.equal(bayesianConfidence([]), null);
  });

  test('single malicious source with high weight → moderate confidence', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.50, skipped: false },
    ];
    const score = bayesianConfidence(results);
    assert.ok(score !== null);
    assert.ok(score >= 40 && score <= 70, `expected 40-70, got ${score}`);
  });

  test('custom prior odds shifts baseline', () => {
    const cleanResults = [
      { source: 'VirusTotal', verdict: 'clean', weight: 0.25, skipped: false },
    ];
    const lowPrior = bayesianConfidence(cleanResults, 0.01); // 1% prior
    const highPrior = bayesianConfidence(cleanResults, 0.5);  // 50% prior
    assert.ok(lowPrior < highPrior, 'higher prior should yield higher confidence for same data');
  });
});

describe('enrichmentMultiplier', () => {
  test('null/undefined → 1.0', () => {
    assert.equal(enrichmentMultiplier(null), 1.0);
    assert.equal(enrichmentMultiplier(undefined), 1.0);
  });

  test('empty object → 1.0', () => {
    assert.equal(enrichmentMultiplier({}), 1.0);
  });

  test('high-risk hoster → 1.15', () => {
    assert.equal(enrichmentMultiplier({ Org: 'AS14061 DigitalOcean, LLC' }), 1.15);
  });

  test('newly registered domain (<30d) → 1.10', () => {
    assert.equal(enrichmentMultiplier({ 'Age (days)': 15 }), 1.10);
  });

  test('recently registered (30-89d) → 1.05', () => {
    assert.equal(enrichmentMultiplier({ 'Age (days)': 60 }), 1.05);
  });

  test('aged domain (≥90d) → 1.0', () => {
    assert.equal(enrichmentMultiplier({ 'Age (days)': 400 }), 1.0);
  });

  test('high-risk hoster + new domain → 1.25', () => {
    assert.equal(enrichmentMultiplier({ Org: 'OVH SAS', 'Age (days)': 10 }), 1.25);
  });

  test('clamped at 1.3 max', () => {
    // Even extreme combos should not exceed 1.3
    const m = enrichmentMultiplier({ Org: 'DigitalOcean', 'Age (days)': 5 });
    assert.ok(m <= 1.3, `expected <= 1.3, got ${m}`);
  });

  test('clamped at 0.5 min', () => {
    // Negative org shouldn't push below 0.5
    assert.ok(enrichmentMultiplier({}) >= 0.5);
  });
});

describe('decayMultiplier', () => {
  test('null/undefined hours → 1.0 (no decay)', () => {
    assert.equal(decayMultiplier(null, 'ip'), 1.0);
    assert.equal(decayMultiplier(undefined, 'ip'), 1.0);
  });

  test('negative hours → 1.0', () => {
    assert.equal(decayMultiplier(-5, 'ip'), 1.0);
  });

  test('zero hours → 1.0 (fresh IOC)', () => {
    assert.equal(decayMultiplier(0, 'ip'), 1.0);
  });

  test('IP at 48 hours → ~0.47 (fast decay)', () => {
    const d = decayMultiplier(48, 'ip');
    // alpha=0.5, tau=168: 1 - (48/168)^0.5 = 1 - 0.535 ≈ 0.465
    assert.ok(d > 0.40 && d < 0.55, `expected ~0.47, got ${d}`);
  });

  test('IP at end-time (168h) → 0', () => {
    assert.equal(decayMultiplier(168, 'ip'), 0);
  });

  test('IP past end-time → 0', () => {
    assert.equal(decayMultiplier(200, 'ip'), 0);
  });

  test('hash decays slower than IP', () => {
    const ipDecay = decayMultiplier(48, 'ip');
    const hashDecay = decayMultiplier(48, 'hash');
    // IP at 48h ≈ 0.47, hash at 48h ≈ 0.9999
    assert.ok(hashDecay > ipDecay, `hash (${hashDecay}) should decay slower than IP (${ipDecay})`);
  });

  test('domain decays slower than IP but faster than hash', () => {
    const ip48 = decayMultiplier(48, 'ip');
    const d48 = decayMultiplier(48, 'domain');
    const hash48 = decayMultiplier(48, 'hash');
    assert.ok(ip48 < d48 && d48 < hash48, `expected ip(${ip48}) < domain(${d48}) < hash(${hash48})`);
  });

  test('unknown type defaults to IP params', () => {
    assert.equal(decayMultiplier(0, 'unknown'), 1.0);
    assert.equal(decayMultiplier(168, 'unknown'), 0);
  });
});

describe('sightingBoost', () => {
  test('0 scans → 0', () => assert.equal(sightingBoost(0), 0));
  test('1 scan → 0', () => assert.equal(sightingBoost(1), 0));
  test('2 scans → 3', () => assert.equal(sightingBoost(2), 3));
  test('5 scans → 5', () => assert.equal(sightingBoost(5), 5));
  test('10 scans → 10', () => assert.equal(sightingBoost(10), 10));
  test('50 scans → 10 (capped)', () => assert.equal(sightingBoost(50), 10));
  test('null → 0', () => assert.equal(sightingBoost(null), 0));
  test('undefined → 0', () => assert.equal(sightingBoost(undefined), 0));
  test('NaN → 0', () => assert.equal(sightingBoost(NaN), 0));
  test('negative → 0', () => assert.equal(sightingBoost(-1), 0));
});

describe('applyTypeWeights', () => {
  test('IP type: AbuseIPDB gets 0.30, VT gets 0.25', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.30, skipped: false, error: null },
      { source: 'AbuseIPDB', verdict: 'malicious', weight: 0.20, skipped: false, error: null },
    ];
    const weighted = applyTypeWeights(results, 'ip');
    assert.equal(weighted[0].weight, 0.25);
    assert.equal(weighted[1].weight, 0.30);
  });

  test('domain type: URLScan gets 0.25, AbuseIPDB gets 0.00', () => {
    const results = [
      { source: 'URLScan.io', verdict: 'malicious', weight: 0.20, skipped: false, error: null },
      { source: 'AbuseIPDB', verdict: 'malicious', weight: 0.20, skipped: false, error: null },
    ];
    const weighted = applyTypeWeights(results, 'domain');
    assert.equal(weighted[0].weight, 0.25);
    assert.equal(weighted[1].weight, 0.00);
  });

  test('hash type: VT gets 0.50, MalwareBazaar 0.20, OTX 0.30', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.30, skipped: false, error: null },
      { source: 'MalwareBazaar', verdict: 'malicious', weight: 0.20, skipped: false, error: null },
      { source: 'AlienVault OTX', verdict: 'malicious', weight: 0.15, skipped: false, error: null },
    ];
    const weighted = applyTypeWeights(results, 'hash');
    assert.equal(weighted[0].weight, 0.50);
    assert.equal(weighted[1].weight, 0.20);
    assert.equal(weighted[2].weight, 0.30);
  });

  test('skipped sources keep original weight', () => {
    const results = [
      { source: 'VirusTotal', skipped: true, weight: 0.30 },
      { source: 'AbuseIPDB', error: 'fail', weight: 0.20 },
    ];
    const weighted = applyTypeWeights(results, 'ip');
    assert.equal(weighted[0].weight, 0.30);
    assert.equal(weighted[1].weight, 0.20);
  });

  test('unknown source keeps original weight', () => {
    const results = [
      { source: 'CustomSource', verdict: 'malicious', weight: 0.50, skipped: false, error: null },
    ];
    const weighted = applyTypeWeights(results, 'ip');
    assert.equal(weighted[0].weight, 0.50);
  });
});

describe('calculateOptimizedConfidence', () => {
  const maliciousResults = [
    { source: 'VirusTotal', verdict: 'malicious', weight: 0.30, skipped: false, error: null, meta: {} },
    { source: 'AbuseIPDB', verdict: 'malicious', weight: 0.20, skipped: false, error: null, meta: {} },
    { source: 'Abuse.ch', verdict: 'malicious', weight: 0.20, skipped: false, error: null, meta: {} },
  ];

  const cleanResults = [
    { source: 'VirusTotal', verdict: 'clean', weight: 0.30, skipped: false, error: null, meta: {} },
    { source: 'AbuseIPDB', verdict: 'clean', weight: 0.20, skipped: false, error: null, meta: {} },
  ];

  test('3 malicious sources → high confidence (>70)', () => {
    const r = calculateOptimizedConfidence(maliciousResults, [], { iocType: 'ip' });
    assert.ok(r.confidence > 70, `expected > 70, got ${r.confidence}`);
    assert.ok(r.corroboration >= 15);
    assert.ok(r.bayesian > 70);
  });

  test('all clean → low confidence (<15)', () => {
    const r = calculateOptimizedConfidence(cleanResults, [], { iocType: 'ip' });
    assert.ok(r.confidence < 15, `expected < 15, got ${r.confidence}`);
  });

  test('single source caps at 50', () => {
    const singleMalicious = [maliciousResults[0]];
    const r = calculateOptimizedConfidence(singleMalicious, [], { iocType: 'ip' });
    assert.ok(r.confidence <= 50, `expected <= 50, got ${r.confidence}`);
  });

  test('stale IOC (>30 days) caps at 40 for IP', () => {
    const r = calculateOptimizedConfidence(maliciousResults, [], {
      iocType: 'ip',
      hoursSinceLastSeen: 31 * 24,
    });
    assert.ok(r.confidence <= 40, `expected <= 40, got ${r.confidence}`);
  });

  test('fresh IOC with high-risk hoster gets enrichment boost', () => {
    const r = calculateOptimizedConfidence(maliciousResults, [], {
      iocType: 'ip',
      enrichmentMeta: { Org: 'DigitalOcean' },
    });
    assert.ok(r.enrichmentMultiplier > 1.0);
  });

  test('sighting boost adds to confidence', () => {
    const r1 = calculateOptimizedConfidence(maliciousResults, [], { iocType: 'ip', scanCount: 0 });
    const r2 = calculateOptimizedConfidence(maliciousResults, [], { iocType: 'ip', scanCount: 10 });
    assert.ok(r2.confidence > r1.confidence, `sighting boost should increase confidence`);
    assert.equal(r2.sightingBoost, 10);
  });

  test('risk factors are included in bonus', () => {
    const factors = [{ bonus: 10 }, { bonus: 15 }];
    const r = calculateOptimizedConfidence(maliciousResults, factors, { iocType: 'ip' });
    assert.ok(r.riskBonus > 0);
  });

  test('risk bonus capped at 25', () => {
    const factors = [{ bonus: 100 }];
    const r = calculateOptimizedConfidence(maliciousResults, factors, { iocType: 'ip' });
    assert.equal(r.riskBonus, 25);
  });

  test('returns all expected fields', () => {
    const r = calculateOptimizedConfidence(maliciousResults, [], { iocType: 'ip' });
    assert.ok('confidence' in r);
    assert.ok('bayesian' in r);
    assert.ok('corroboration' in r);
    assert.ok('riskBonus' in r);
    assert.ok('sightingBoost' in r);
    assert.ok('enrichmentMultiplier' in r);
    assert.ok('decay' in r);
    assert.ok('activeSourceCount' in r);
    assert.ok('baseline' in r);
    assert.ok('floor' in r);
    assert.ok('bonus' in r);
  });

  test('null opts uses defaults without crashing', () => {
    const r = calculateOptimizedConfidence(maliciousResults, [], null);
    assert.ok(Number.isFinite(r.confidence));
  });

  test('empty results → confidence 0', () => {
    const r = calculateOptimizedConfidence([], [], { iocType: 'ip' });
    assert.equal(r.confidence, 0);
  });

  test('decay reduces confidence proportionally', () => {
    const fresh = calculateOptimizedConfidence(maliciousResults, [], { iocType: 'ip', hoursSinceLastSeen: 0 });
    const stale = calculateOptimizedConfidence(maliciousResults, [], { iocType: 'ip', hoursSinceLastSeen: 72 });
    assert.ok(fresh.confidence > stale.confidence, `fresh (${fresh.confidence}) > stale (${stale.confidence})`);
  });

  test('domain type gets URLScan-weighted results', () => {
    const domainResults = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.30, skipped: false, error: null, meta: {} },
      { source: 'URLScan.io', verdict: 'malicious', weight: 0.20, skipped: false, error: null, meta: {} },
      { source: 'Abuse.ch', verdict: 'malicious', weight: 0.20, skipped: false, error: null, meta: {} },
    ];
    const r = calculateOptimizedConfidence(domainResults, [], { iocType: 'domain' });
    assert.ok(r.confidence > 50, `domain with 3 malicious should be > 50, got ${r.confidence}`);
  });
});

// ── Comparison: optimized vs legacy ──────────────────────────────────────

describe('optimized vs legacy comparison', () => {
  test('multi-source malicious: optimized is high-confidence with corroboration', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.30, skipped: false, error: null, meta: {} },
      { source: 'AbuseIPDB', verdict: 'malicious', weight: 0.20, skipped: false, error: null, meta: {} },
      { source: 'Abuse.ch', verdict: 'malicious', weight: 0.20, skipped: false, error: null, meta: {} },
    ];
    const factors = collectRiskFactors(results);
    const optimized = calculateOptimizedConfidence(results, factors, { iocType: 'ip' });
    assert.ok(optimized.confidence >= 70, `optimized (${optimized.confidence}) should be >= 70`);
    assert.ok(optimized.corroboration >= 15, 'should have corroboration bonus');
  });

  test('single source: optimized caps at 50 (more conservative)', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'malicious', weight: 0.30, skipped: false, error: null, meta: { Malicious: 10, 'Total Engines': 90 } },
    ];
    const factors = collectRiskFactors(results);
    const optimized = calculateOptimizedConfidence(results, factors, { iocType: 'ip' });
    assert.ok(optimized.confidence <= 50, `single source should cap at 50, got ${optimized.confidence}`);
  });

  test('all clean: both return low confidence', () => {
    const results = [
      { source: 'VirusTotal', verdict: 'clean', weight: 0.30, skipped: false, error: null, meta: {} },
      { source: 'AbuseIPDB', verdict: 'clean', weight: 0.20, skipped: false, error: null, meta: {} },
    ];
    const factors = [];
    const legacy = calcConfidenceWithFloors(results, factors);
    const optimized = calculateOptimizedConfidence(results, factors, { iocType: 'ip' });
    assert.ok(legacy.confidence < 15);
    assert.ok(optimized.confidence < 15);
  });
});
