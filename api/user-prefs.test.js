const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { sanitizeIds } = require('./user-prefs');

describe('sanitizeIds', () => {
  test('keeps known tab ids in order', () => {
    assert.deepEqual(sanitizeIds(['json', 'formatter', 'ioc-scan']), ['json', 'formatter', 'ioc-scan']);
  });

  test('drops unknown ids and non-strings', () => {
    assert.deepEqual(sanitizeIds(['formatter', 'bogus', 5, null, 'json']), ['formatter', 'json']);
  });

  test('dedupes repeated ids (first wins)', () => {
    assert.deepEqual(sanitizeIds(['json', 'json', 'merger']), ['json', 'merger']);
  });

  test('returns [] for non-array input', () => {
    assert.deepEqual(sanitizeIds(undefined), []);
    assert.deepEqual(sanitizeIds('formatter'), []);
    assert.deepEqual(sanitizeIds(null), []);
  });
});
