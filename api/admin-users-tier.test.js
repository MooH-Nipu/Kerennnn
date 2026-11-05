'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { canAssignRole, canManageTarget } = require('./admin/users');

test('l2 cannot mint or promote to admin', () => {
  assert.equal(canAssignRole('l2', 'admin'), false);
  assert.equal(canAssignRole('l2', 'soc_lead'), true);
  assert.equal(canAssignRole('l2', 'l1'), true);
  assert.equal(canAssignRole('admin', 'admin'), true);
});

test('l2 cannot modify or delete an admin account', () => {
  assert.equal(canManageTarget('l2', 'admin'), false);
  assert.equal(canManageTarget('l2', 'l2'), true);
  assert.equal(canManageTarget('l2', 'l1'), true);
  assert.equal(canManageTarget('admin', 'admin'), true);
});
