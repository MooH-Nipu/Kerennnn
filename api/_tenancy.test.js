const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { getRoleContext, resolveTeamContext } = require('./_tenancy');

describe('role tenancy context', () => {
  test('legacy PAC role needs explicit PAC membership', () => {
    assert.deepEqual(getRoleContext('pac'), {
      assignedTeam: null, allowedTeams: [], canSwitchTeam: false,
    });
    assert.equal(resolveTeamContext({ role: 'pac', teamAccess: ['PAC'] }, undefined), 'PAC');
  });

  test('Charlie analyst cannot override context to PAC', () => {
    assert.throws(
      () => resolveTeamContext({ role: 'charlie', teamAccess: ['CHARLIE'] }, 'PAC'),
      error => error.status === 403 && error.code === 'ERR_TEAM_ACCESS_DENIED'
    );
  });

  test('SOC lead must select a valid allowed context', () => {
    assert.throws(
      () => resolveTeamContext({ role: 'soc_lead', teamAccess: ['PAC', 'CHARLIE'] }, undefined),
      error => error.status === 400 && error.code === 'ERR_TEAM_CONTEXT_REQUIRED'
    );
    assert.equal(resolveTeamContext({ role: 'soc_lead', teamAccess: ['PAC', 'CHARLIE'] }, 'charlie'), 'CHARLIE');
  });

  test('legacy L2 remains a lead during migration', () => {
    assert.equal(resolveTeamContext({ role: 'l2', teamAccess: ['PAC', 'CHARLIE'] }, 'PAC'), 'PAC');
    assert.equal(resolveTeamContext({ role: 'l2', teamAccess: ['PAC', 'CHARLIE'] }, 'CHARLIE'), 'CHARLIE');
  });

  test('admin can switch between PAC and CHARLIE', () => {
    assert.deepEqual(getRoleContext('admin', ['PAC', 'CHARLIE']), {
      assignedTeam: null, allowedTeams: ['PAC', 'CHARLIE'], canSwitchTeam: true,
    });
    assert.equal(resolveTeamContext({ role: 'admin', teamAccess: ['PAC', 'CHARLIE'] }, 'PAC'), 'PAC');
    assert.equal(resolveTeamContext({ role: 'admin', teamAccess: ['PAC', 'CHARLIE'] }, 'CHARLIE'), 'CHARLIE');
  });

  test('explicit PAC and CHARLIE memberships allow either team regardless of scalar role', () => {
    assert.deepEqual(getRoleContext('l1', ['CHARLIE', 'PAC']), {
      assignedTeam: null, allowedTeams: ['PAC', 'CHARLIE'], canSwitchTeam: true,
    });
    assert.equal(resolveTeamContext({ role: 'l1', teamAccess: ['PAC', 'CHARLIE'] }, 'PAC'), 'PAC');
    assert.equal(resolveTeamContext({ role: 'l1', teamAccess: ['PAC', 'CHARLIE'] }, 'CHARLIE'), 'CHARLIE');
  });

  test('single explicit membership remains isolated to its team', () => {
    assert.deepEqual(getRoleContext('l1', ['CHARLIE']), {
      assignedTeam: 'CHARLIE', allowedTeams: ['CHARLIE'], canSwitchTeam: false,
    });
    assert.equal(resolveTeamContext({ role: 'l1', teamAccess: ['CHARLIE'] }), 'CHARLIE');
    assert.throws(
      () => resolveTeamContext({ role: 'l1', teamAccess: ['CHARLIE'] }, 'PAC'),
      error => error.status === 403 && error.code === 'ERR_TEAM_ACCESS_DENIED'
    );
  });

  test('legacy PAC endpoint cannot bypass lead context selection', () => {
    const source = require('node:fs').readFileSync(require('node:path').join(__dirname, 'scan-merger.js'), 'utf8');
    assert.match(source, /getRoleContext\(req\.auth\.role, req\.auth\.teamAccess\)/);
    assert.match(source, /allowedTeams\.includes\('PAC'\)/);
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
