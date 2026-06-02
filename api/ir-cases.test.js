const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { sanitizeSearchTerm } = require('./ir-cases');

describe('sanitizeSearchTerm', () => {
  test('strips PostgREST filter-control characters', () => {
    assert.equal(sanitizeSearchTerm('a,b(c)d*e%f\\g'), 'abcdefg');
  });

  test('trims surrounding whitespace', () => {
    assert.equal(sanitizeSearchTerm('  hello  '), 'hello');
  });

  test('neutralizes an or() filter-breakout payload', () => {
    const evil = 'x),role.eq.admin,(title.ilike.*';
    const safe = sanitizeSearchTerm(evil);
    assert.ok(!/[,()*%\\]/.test(safe), `unexpected control char left in: ${safe}`);
  });

  test('handles null / undefined', () => {
    assert.equal(sanitizeSearchTerm(undefined), '');
    assert.equal(sanitizeSearchTerm(null), '');
  });

  test('leaves ordinary search text intact', () => {
    assert.equal(sanitizeSearchTerm('phishing email 2026'), 'phishing email 2026');
  });
});
