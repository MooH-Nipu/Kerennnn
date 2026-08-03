const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { createScanBudget } = require('./_scan-budget');

describe('per-user scan budget', () => {
  test('allows requests up to the operation limit', () => {
    const budget = createScanBudget({ vt: 2 }, 60_000);
    assert.deepEqual(budget.consume('user-a', 'vt', 1000), { allowed: true, remaining: 1, retryAfter: 0 });
    assert.deepEqual(budget.consume('user-a', 'vt', 1001), { allowed: true, remaining: 0, retryAfter: 0 });
  });

  test('rejects requests over limit with retry time', () => {
    const budget = createScanBudget({ correlate: 1 }, 60_000);
    budget.consume('user-a', 'correlate', 1000);
    assert.deepEqual(budget.consume('user-a', 'correlate', 2000), { allowed: false, remaining: 0, retryAfter: 59 });
  });

  test('isolates users and operations', () => {
    const budget = createScanBudget({ vt: 1, correlate: 1 }, 60_000);
    budget.consume('user-a', 'vt', 1000);
    assert.equal(budget.consume('user-b', 'vt', 1001).allowed, true);
    assert.equal(budget.consume('user-a', 'correlate', 1001).allowed, true);
  });

  test('resets after window', () => {
    const budget = createScanBudget({ vt: 1 }, 60_000);
    budget.consume('user-a', 'vt', 1000);
    assert.equal(budget.consume('user-a', 'vt', 61_001).allowed, true);
  });
});
