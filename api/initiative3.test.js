'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

const { pickCvss } = require('./cve.js');
const { reduceBundle } = require('./attack.js');

test('pickCvss', async (t) => {
  await t.test('prefers CVSS v3.1 over v3.0 and v2', () => {
    const metrics = {
      cvssMetricV2: [{ cvssData: { version: '2.0', baseScore: 5 }, baseSeverity: 'MEDIUM' }],
      cvssMetricV30: [{ cvssData: { version: '3.0', baseScore: 7.5, baseSeverity: 'HIGH', vectorString: 'V30' } }],
      cvssMetricV31: [{ cvssData: { version: '3.1', baseScore: 9.8, baseSeverity: 'CRITICAL', vectorString: 'V31' } }],
    };
    const r = pickCvss(metrics);
    assert.equal(r.version, '3.1');
    assert.equal(r.score, 9.8);
    assert.equal(r.severity, 'CRITICAL');
    assert.equal(r.vector, 'V31');
  });

  await t.test('reads v2 severity from the metric wrapper (not cvssData)', () => {
    const r = pickCvss({ cvssMetricV2: [{ cvssData: { version: '2.0', baseScore: 4.3 }, baseSeverity: 'LOW' }] });
    assert.equal(r.version, '2.0');
    assert.equal(r.score, 4.3);
    assert.equal(r.severity, 'LOW');
  });

  await t.test('returns null when no metrics present', () => {
    assert.equal(pickCvss(null), null);
    assert.equal(pickCvss({}), null);
  });
});

test('reduceBundle', async (t) => {
  const bundle = {
    objects: [
      {
        type: 'attack-pattern',
        name: 'Command and Scripting Interpreter',
        description: 'Adversaries may abuse command interpreters.',
        kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }],
        x_mitre_platforms: ['Windows', 'Linux'],
        x_mitre_detection: 'Monitor process execution.',
        x_mitre_is_subtechnique: false,
        external_references: [
          { source_name: 'mitre-attack', external_id: 'T1059', url: 'https://attack.mitre.org/techniques/T1059/' },
        ],
      },
      { type: 'attack-pattern', name: 'Revoked', revoked: true, external_references: [{ source_name: 'mitre-attack', external_id: 'T9999' }] },
      { type: 'attack-pattern', name: 'Deprecated', x_mitre_deprecated: true, external_references: [{ source_name: 'mitre-attack', external_id: 'T9998' }] },
      { type: 'attack-pattern', name: 'No mitre ref', external_references: [{ source_name: 'capec', external_id: 'CAPEC-1' }] },
      { type: 'course-of-action', name: 'Not a technique' },
    ],
  };

  await t.test('keeps only live techniques with a mitre-attack id', () => {
    const techniques = reduceBundle(bundle);
    assert.equal(techniques.length, 1);
    const tq = techniques[0];
    assert.equal(tq.id, 'T1059');
    assert.deepEqual(tq.tactics, ['execution']);
    assert.deepEqual(tq.platforms, ['Windows', 'Linux']);
    assert.equal(tq.isSubtechnique, false);
  });

  await t.test('handles an empty / malformed bundle', () => {
    assert.deepEqual(reduceBundle({}), []);
    assert.deepEqual(reduceBundle(null), []);
  });
});
