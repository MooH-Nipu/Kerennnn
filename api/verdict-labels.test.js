const test = require('node:test');
const assert = require('node:assert/strict');
const { labelFromConfidence, calcVtVerdict, vtStats } = require('./_verdict');

test('confidence labels follow the documented thresholds', () => {
  assert.equal(labelFromConfidence(78), 'HIGH RISK');
  assert.equal(labelFromConfidence(70), 'HIGH RISK');
  assert.equal(labelFromConfidence(69), 'MEDIUM RISK');
  assert.equal(labelFromConfidence(40), 'MEDIUM RISK');
  assert.equal(labelFromConfidence(15), 'LOW RISK');
  assert.equal(labelFromConfidence(14), 'LIKELY CLEAN');
  assert.equal(labelFromConfidence(null), 'UNKNOWN');
});

test('VT verdict mirrors the UI rules', () => {
  assert.equal(calcVtVerdict(9, 2, 71), 'MALICIOUS');
  assert.equal(calcVtVerdict(1, 0, 71), 'SUSPICIOUS');
  assert.equal(calcVtVerdict(0, 0, 71), 'CLEAN');
  assert.equal(calcVtVerdict(0, 0, 0), 'UNKNOWN');
});

test('vtStats flattens the /api/vt body', () => {
  const stats = vtStats({
    data: { attributes: {
      last_analysis_stats: { malicious: 9, suspicious: 2, undetected: 60, harmless: 0, timeout: 0 },
      reputation: -12, country: 'NL', asn: 15169, as_owner: 'GOOGLE',
    } },
  });
  assert.equal(stats.total, 71);
  assert.equal(stats.verdict, 'MALICIOUS');
  assert.equal(stats.country, 'NL');
  assert.equal(stats.asOwner, 'GOOGLE');
  assert.equal(vtStats(null).verdict, 'UNKNOWN');
});
