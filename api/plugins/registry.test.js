const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { PLUGINS, getAvailablePlugins, getPluginTimeout, DEFAULT_TIMEOUT_MS } = require('./index');

describe('Plugin registry', () => {
  test('registry declares supported types independently from configured keys', () => {
    const ipPlugins = PLUGINS.filter(p => p.supportsType('ip'));
    const domainPlugins = PLUGINS.filter(p => p.supportsType('domain'));
    const hashPlugins = PLUGINS.filter(p => p.supportsType('hash'));

    // VT supports all types
    assert.ok(ipPlugins.some(p => p.name === 'VirusTotal'));
    assert.ok(domainPlugins.some(p => p.name === 'VirusTotal'));
    assert.ok(hashPlugins.some(p => p.name === 'VirusTotal'));

    // AbuseIPDB is IP-only
    assert.ok(ipPlugins.some(p => p.name === 'AbuseIPDB'));
    assert.ok(!domainPlugins.some(p => p.name === 'AbuseIPDB'));
    assert.ok(!hashPlugins.some(p => p.name === 'AbuseIPDB'));

    // MalwareBazaar is hash-only
    assert.ok(!ipPlugins.some(p => p.name === 'MalwareBazaar'));
    assert.ok(!domainPlugins.some(p => p.name === 'MalwareBazaar'));
    assert.ok(hashPlugins.some(p => p.name === 'MalwareBazaar'));

    // URLScan is domain-only
    assert.ok(!ipPlugins.some(p => p.name === 'URLScan.io'));
    assert.ok(domainPlugins.some(p => p.name === 'URLScan.io'));
    assert.ok(!hashPlugins.some(p => p.name === 'URLScan.io'));
  });

  test('getAvailablePlugins filters by availability', () => {
    // VirusTotal always available (IP cache reuse)
    const allPlugins = getAvailablePlugins('ip');
    assert.ok(allPlugins.some(p => p.name === 'VirusTotal'));

    // Enrichment always available (RDAP is keyless)
    assert.ok(allPlugins.some(p => p.name === 'Enrichment'));
  });

  test('getPluginTimeout returns custom timeout for URLScan', () => {
    const plugins = getAvailablePlugins('domain');
    const urlscan = plugins.find(p => p.name === 'URLScan.io');
    if (urlscan) {
      assert.equal(getPluginTimeout(urlscan), 45_000);
    }
  });

  test('getPluginTimeout returns default for other plugins', () => {
    const plugins = getAvailablePlugins('ip');
    const vt = plugins.find(p => p.name === 'VirusTotal');
    if (vt) {
      assert.equal(getPluginTimeout(vt), DEFAULT_TIMEOUT_MS);
    }
  });
});
