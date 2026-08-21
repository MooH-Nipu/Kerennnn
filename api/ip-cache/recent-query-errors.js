'use strict';

function firstQueryError(results) {
  return results.find(result => result?.error)?.error || null;
}

module.exports = { firstQueryError };
