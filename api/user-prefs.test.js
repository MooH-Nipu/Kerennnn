const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { sanitizeIds, sanitizeLabels, sanitizeLayout, sanitizeTutorialDismissed } = require('./user-prefs');

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

  test('keeps admin usage as a supported tab', () => {
    assert.deepEqual(sanitizeIds(['admin-usage']), ['admin-usage']);
  });
});

describe('sanitizeLayout', () => {
  test('keeps custom groups, group order, and tab order', () => {
    assert.deepEqual(sanitizeLayout([
      { id: 'custom-hunt', label: 'Hunt', tabs: ['cve', 'ioc-scan'] },
      { id: 'work', label: 'Work', tabs: ['history'] },
    ]), [
      { id: 'custom-hunt', label: 'Hunt', tabs: ['cve', 'ioc-scan'] },
      { id: 'work', label: 'Work', tabs: ['history'] },
    ]);
  });

  test('drops bad groups, settings, unknown tabs, and duplicate tabs', () => {
    assert.deepEqual(sanitizeLayout([
      { id: 'bad space', label: 'Bad', tabs: ['json'] },
      { id: 'work', label: '  Work  ', tabs: ['ioc-scan', 'settings', 'bogus', 'ioc-scan'] },
      { id: 'utilities', label: 'Utils', tabs: ['ioc-scan', 'json'] },
    ]), [
      { id: 'work', label: 'Work', tabs: ['ioc-scan'] },
      { id: 'utilities', label: 'Utils', tabs: ['json'] },
    ]);
  });

  test('limits layout to 12 groups and labels to 24 characters', () => {
    const groups = Array.from({ length: 14 }, (_, i) => ({ id: `group-${i}`, label: '1234567890123456789012345', tabs: [] }));
    const result = sanitizeLayout(groups);
    assert.equal(result.length, 12);
    assert.equal(result[0].label, '123456789012345678901234');
  });
});

describe('sanitizeTutorialDismissed', () => {
  test('accepts only explicit true', () => {
    assert.equal(sanitizeTutorialDismissed(true), true);
    assert.equal(sanitizeTutorialDismissed(false), false);
    assert.equal(sanitizeTutorialDismissed('true'), false);
    assert.equal(sanitizeTutorialDismissed(1), false);
  });
});

describe('sanitizeLabels', () => {
  test('keeps trimmed labels for known ids', () => {
    assert.deepEqual(sanitizeLabels({ json: '  Parser  ', formatter: 'Text Tools' }, ['json', 'formatter']), {
      json: 'Parser',
      formatter: 'Text Tools',
    });
  });

  test('drops unknown, empty, non-string, and control-character labels', () => {
    assert.deepEqual(sanitizeLabels({
      json: '',
      formatter: 'Bad\nLabel',
      bogus: 'Nope',
      merger: 5,
      history: 'Timeline',
    }, ['json', 'formatter', 'merger', 'history']), { history: 'Timeline' });
  });

  test('limits labels to 24 characters', () => {
    assert.deepEqual(sanitizeLabels({ json: '1234567890123456789012345' }, ['json']), {
      json: '123456789012345678901234',
    });
  });
});
