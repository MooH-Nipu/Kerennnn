'use strict';

// Base class for threat-intelligence plugins. Each source (VT, AbuseIPDB, etc.)
// subclasses this and implements check(). correlate.js discovers plugins via
// the registry in ./index.js and calls them in parallel.
//
// Contract:
// - name: human-readable source name (used in response `source` field)
// - supportedTypes: array of IOC types this plugin handles ['ip','domain','hash','url']
// - check(ioc, type): async, returns { source, verdict?, score?, weight?, meta?, link?, skipped?, error?, keyPrefix? }
// - isAvailable(): sync, true if plugin has required config (API keys etc.)
class TIPlugin {
  constructor() {
    this.name = '';
    this.supportedTypes = [];
  }

  async check() {
    throw new Error(`${this.constructor.name}: check() not implemented`);
  }

  isAvailable() {
    // Default: available. Override to gate on API keys / config.
    return true;
  }

  supportsType(type) {
    return this.supportedTypes.includes(type);
  }
}

module.exports = { TIPlugin };
