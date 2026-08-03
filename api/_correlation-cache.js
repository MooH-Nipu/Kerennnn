'use strict';

// Failed source rows stay visible to analysts, but must never make cache final.
function isCompleteCorrelationPayload(payload) {
  if (!payload || !Array.isArray(payload.sources) || payload.sources.length === 0) return false;
  return payload.sources.every(source => source && !source.error && source.source !== 'Unknown');
}

module.exports = { isCompleteCorrelationPayload };