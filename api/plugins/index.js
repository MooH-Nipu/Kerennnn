'use strict';
// Plugin registry: every TI source subclasses TIPlugin in its own file here.
// correlate.js calls getAvailablePlugins(type) and runs them in parallel.
//
// To add a new source: create a plugin file in this directory, instantiate it
// below. (Auto-discovery by directory scan intentionally avoided — an explicit
// list keeps load order deterministic and avoids requiring fs tricks that break
// under bundlers. Files prefixed with `_` are helpers, not plugins.)

const { VirusTotalPlugin } = require('./virustotal');
const { AbuseIPDBPlugin } = require('./abuseipdb');
const { AbuseChPlugin } = require('./abusech');
const { MalwareBazaarPlugin } = require('./malwarebazaar');
const { OTXPlugin } = require('./otx');
const { URLScanPlugin } = require('./urlscan');
const { EnrichmentPlugin } = require('./enrichment');

// Order preserved from the pre-plugin correlate.js check list.
const PLUGINS = [
  new VirusTotalPlugin(),
  new OTXPlugin(),
  new AbuseIPDBPlugin(),
  new MalwareBazaarPlugin(),
  new AbuseChPlugin(),
  new EnrichmentPlugin(),
  new URLScanPlugin(),
];

// Default per-source timeout. Was 15s; the slowest legitimate source measured
// live (OTX full-domain general endpoint) answers in ~2.6s, so 15s was 6x the
// real p95 and every straggler set the floor for the whole Promise.all. URLScan
// still overrides via plugin.timeoutMs for its submit+poll cycle.
const DEFAULT_TIMEOUT_MS = 8_000;

function getAvailablePlugins(type) {
  return PLUGINS.filter(p => p.supportsType(type) && p.isAvailable());
}

function getPluginTimeout(plugin) {
  return Number.isFinite(plugin.timeoutMs) ? plugin.timeoutMs : DEFAULT_TIMEOUT_MS;
}

module.exports = { PLUGINS, getAvailablePlugins, getPluginTimeout, DEFAULT_TIMEOUT_MS };
