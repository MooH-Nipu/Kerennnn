'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const source = path => readFileSync(join(__dirname, '..', path), 'utf8');

test('sample digest uses Web Crypto for known bytes, rejects oversize before reading', async () => {
  const { sha256Sample, MAX_SAMPLE_BYTES } = await import('../src/lib/sample-relationships.mjs');
  const file = { size: 3, arrayBuffer: async () => Uint8Array.from([97, 98, 99]).buffer };
  assert.equal(await sha256Sample(file, webcrypto), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  let read = false;
  await assert.rejects(sha256Sample({ size: MAX_SAMPLE_BYTES + 1, arrayBuffer: async () => { read = true; } }, webcrypto), /32 MiB/);
  assert.equal(read, false);
  await assert.rejects(sha256Sample(file, {}), /Web Crypto/);
});

test('one-hop graph validates source, bounds pairs, dedupes, rejects malformed and inferred edges', async () => {
  const { resolutionEdges, reverseCandidates, MAX_RELATION_EDGES, MAX_REVERSE_CANDIDATES } = await import('../src/lib/sample-relationships.mjs');
  const records = [
    { host: 'A.Example.com.', ip: '1.2.3.4' }, { host: 'a.example.com', ip: '1.2.3.4' },
    { host: 'foreign.net', ip: '1.2.3.4' }, { host: 'b.example.com', ip: '999.2.3.4' },
    { host: 'bad name.example.com', ip: '1.2.3.4' },
    ...Array.from({ length: 50 }, (_, i) => ({ host: `host${i}.example.com`, ip: `1.2.3.${i}` })),
  ];
  const domain = resolutionEdges('example.com', 'domain', [{ type: 'domain', ioc: 'example.com', records }]);
  assert.equal(domain.length, MAX_RELATION_EDGES);
  assert.deepEqual(domain[0], { domain: 'a.example.com', ip: '1.2.3.4' });
  assert.deepEqual(resolutionEdges('example.com', 'domain', [{ type: 'domain', ioc: 'other.com', records }]), []);
  assert.deepEqual(resolutionEdges('not valid', 'domain', [{ type: 'domain', ioc: 'not valid', records }]), []);
  assert.deepEqual(resolutionEdges('1.2.3.4', 'ip', [{ type: 'ip', ioc: '1.2.3.4', records: [{ host: 'a.example.com' }] }]), []);
  assert.deepEqual(resolutionEdges('1.2.3.4', 'ip', [{ type: 'domain', ioc: 'a.example.com', records: [{ host: 'a.example.com', ip: '1.2.3.4' }, { host: 'other.example.com', ip: '1.2.3.4' }, { host: 'a.example.com', ip: '4.3.2.1' }] }]), [{ domain: 'a.example.com', ip: '1.2.3.4' }]);
  assert.equal(reverseCandidates({ records: [...records, null, {}, { host: 'a.example.com' }] }).length, MAX_REVERSE_CANDIDATES);
});

test('sample file only enters digest; network scanner accepts hash string, never sample bytes', () => {
  const ui = source('src/pages/IocScanTab.tsx');
  const helper = source('src/lib/sample-relationships.mjs');
  const api = source('src/lib/api.ts');
  assert.match(ui, /const hash = await sha256Sample\(file\)/);
  assert.match(ui, /setInput\(hash\)/);
  assert.match(ui, /runScan\(val\)/);
  assert.doesNotMatch(ui, /runScan\(file\)|api\.scan\.[\w]+\(file\)|FormData\(/);
  assert.match(helper, /cryptoApi\.subtle\.digest\('SHA-256', bytes\)/);
  assert.match(api, /encodeURIComponent\(ioc\)/);
  assert.doesNotMatch(api, /sampleUpload|uploadSample/);
});
