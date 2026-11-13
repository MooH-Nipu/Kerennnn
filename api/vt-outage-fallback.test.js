'use strict';
/**
 * VT-outage and country-fallback contract:
 * - VT failure must not abort a scan; correlation providers still run.
 * - IP country falls back to successful Enrichment metadata when VT has none.
 * - A provider error stays visible on the card instead of rendering believable
 *   zero values.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');

test('VT failure is non-fatal and correlation still runs', () => {
  const hook = source('src/hooks/useVtScan.ts');
  // VT error is captured, not rethrown out of the scan loop.
  assert.match(hook, /vtFailed = true/);
  assert.doesNotMatch(hook, /RESOLVE_ERROR/);
  // The failed VT result keeps the provider error on the item.
  assert.match(hook, /result = \{ error: .* \} as ScanItem\['result'\]/);
  // Cached correlation is skipped after a VT failure so independent providers
  // get a fresh chance to answer.
  assert.match(hook, /if \(!vtFailed\)/);
});

test('IP country falls back to successful Enrichment metadata when VT has none', () => {
  const hook = source('src/hooks/useVtScan.ts');
  assert.match(hook, /Enrichment/);
  assert.match(hook, /RIR Country/);
  assert.match(hook, /^\s*if \(\/\^\[A-Z\]\{2\}\$\//m);
  assert.match(hook, /const vtCountry = typeof attrs\?\.country === 'string'/);
});

test('VtCard surfaces a provider error instead of believable zero values', () => {
  const card = source('src/components/vt/VtCard.tsx');
  // result.error from a failed VT call becomes the card error.
  assert.match(card, /const providerError = item\.error \|\| String\(\(item\.result as Record<string, unknown> \| null\)\?\.error \|\| ''\)/);
  assert.match(card, /function ProviderErrorNotice/);
  // Detection bar and VT verdict must not render as if VT answered.
  assert.match(card, /\{!providerError && <DetectionBar/);
  assert.match(card, /value: providerError \? 'UNAVAILABLE' : verdictMeta\(item, v\)\.label/);
  // Detection counters must read '—' on error, never a believable zero.
  assert.match(card, /\{ label: 'Malicious',\s+value: providerError \? '—' : mal,/);
  assert.match(card, /\{ label: 'Suspicious', value: providerError \? '—' : sus,/);
  assert.match(card, /\{ label: 'Undetected', value: providerError \? '—' : \(s\.undetected \?\? 0\) \}/);
  // Errored items still render an IP/hash/domain card (with the notice) rather
  // than falling through to the generic error card.
  assert.match(card, /const providerError = item\.error[\s\S]{0,200}if \(item\.type === 'ip'\)/);
});

test('IP card reads Enrichment country with the same precedence as the hook', () => {
  const card = source('src/components/vt/VtCard.tsx');
  assert.match(card, /source\.source === 'Enrichment' && !source\.error && !source\.skipped/);
  assert.match(card, /source\.meta\?\.Country \?\? source\.meta\?\.\['RIR Country'\]/);
  assert.match(card, /const country = String\(a\.country \?\? enrichmentCountry \?\? ''\)/);
});
