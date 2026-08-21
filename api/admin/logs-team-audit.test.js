const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mapTeamAudit, canReadSystemLogs } = require('./logs');

test('team filter audit maps into existing activity log contract', () => {
  assert.deepEqual(mapTeamAudit({
    id: 7,
    actor_username: 'lead',
    team: 'CHARLIE',
    operation: 'delete',
    item_count: 2,
    execution_time_ms: 18,
    status: 'ok',
    detail: { requested: 2 },
    created_at: '2026-08-20T00:00:00Z',
  }), {
    id: 'team-filter-7',
    actor_username: 'lead',
    action: 'team_filter.delete',
    target: 'CHARLIE',
    detail: { status: 'ok', item_count: 2, execution_time_ms: 18, requested: 2 },
    created_at: '2026-08-20T00:00:00Z',
  });
});

test('SOC Lead cannot read system audit or login attempts', () => {
  assert.equal(canReadSystemLogs('soc_lead'), false);
  assert.equal(canReadSystemLogs('admin'), true);
  assert.equal(canReadSystemLogs('l2'), true);
});
