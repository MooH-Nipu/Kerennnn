'use strict';

const SCORING_VERSION = 3;

// Failed source rows stay visible to analysts, but must never make cache final.
// Version mismatch forces one fresh correlation after methodology changes.
function isCompleteCorrelationPayload(payload) {
  if (payload?.scoring?.version !== SCORING_VERSION) return false;
  if (!Array.isArray(payload.sources) || payload.sources.length === 0) return false;
  return payload.sources.every(source => source && !source.error && source.source !== 'Unknown');
}

module.exports = { isCompleteCorrelationPayload };