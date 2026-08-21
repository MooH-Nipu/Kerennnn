const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { getRoleContext, resolveTeamContext } = require('./_tenancy');

describe('role tenancy context', () => {
  test('PAC analyst is fixed to PAC', () => {
    assert.deepEqual(getRoleContext('pac'), {
      assignedTeam: 'PAC', allowedTeams: ['PAC'], canSwitchTeam: false,
    });
    assert.equal(resolveTeamContext({ role: 'pac' }, undefined), 'PAC');
  });

  test('Charlie analyst cannot override context to PAC', () => {
    assert.throws(
      () => resolveTeamContext({ role: 'charlie' }, 'PAC'),
      error => error.status === 403 && error.code === 'ERR_TEAM_ACCESS_DENIED'
    );
  });

  test('SOC lead must select a valid allowed context', () => {
    assert.throws(
      () => resolveTeamContext({ role: 'soc_lead' }, undefined),
      error => error.status === 400 && error.code === 'ERR_TEAM_CONTEXT_REQUIRED'
    );
    assert.equal(resolveTeamContext({ role: 'soc_lead' }, 'charlie'), 'CHARLIE');
  });

  test('legacy L2 remains a lead during migration', () => {
    assert.equal(resolveTeamContext({ role: 'l2' }, 'PAC'), 'PAC');
    assert.equal(resolveTeamContext({ role: 'l2' }, 'CHARLIE'), 'CHARLIE');
  });

  test('admin can switch between PAC and CHARLIE', () => {
    assert.deepEqual(getRoleContext('admin'), {
      assignedTeam: null, allowedTeams: ['PAC', 'CHARLIE'], canSwitchTeam: true,
    });
    assert.equal(resolveTeamContext({ role: 'admin' }, 'PAC'), 'PAC');
    assert.equal(resolveTeamContext({ role: 'admin' }, 'CHARLIE'), 'CHARLIE');
  });

  test('legacy PAC endpoint cannot bypass lead context selection', () => {
    const source = require('node:fs').readFileSync(require('node:path').join(__dirname, 'scan-merger.js'), 'utf8');
    assert.match(source, /const PAC_ROLES = \['pac'\]/);
  });

  test('L1 and invalid contexts are denied', () => {
    assert.throws(
      () => resolveTeamContext({ role: 'l1' }, 'PAC'),
      error => error.status === 403 && error.code === 'ERR_TEAM_ACCESS_DENIED'
    );
    assert.throws(
      () => resolveTeamContext({ role: 'soc_lead' }, 'not-a-team'),
      error => error.status === 400 && error.code === 'ERR_INVALID_TEAM_CONTEXT'
    );
  });
});
