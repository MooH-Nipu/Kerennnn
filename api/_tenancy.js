'use strict';

const TEAM_CONTEXT = Object.freeze({
  pac: { assignedTeam: 'PAC', allowedTeams: ['PAC'], canSwitchTeam: false },
  charlie: { assignedTeam: 'CHARLIE', allowedTeams: ['CHARLIE'], canSwitchTeam: false },
  soc_lead: { assignedTeam: null, allowedTeams: ['PAC', 'CHARLIE'], canSwitchTeam: true },
  l2: { assignedTeam: null, allowedTeams: ['PAC', 'CHARLIE'], canSwitchTeam: true },
  admin: { assignedTeam: null, allowedTeams: ['PAC', 'CHARLIE'], canSwitchTeam: true },
  l1: { assignedTeam: null, allowedTeams: [], canSwitchTeam: false },
});

function tenancyError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function getRoleContext(role) {
  const value = TEAM_CONTEXT[String(role || '').toLowerCase()];
  return value ? { ...value, allowedTeams: [...value.allowedTeams] } : {
    assignedTeam: null, allowedTeams: [], canSwitchTeam: false,
  };
}

function normalizeTeamContext(value) {
  if (value == null || String(value).trim() === '') return null;
  const team = String(value).trim().toUpperCase();
  if (team !== 'PAC' && team !== 'CHARLIE') {
    throw tenancyError(400, 'ERR_INVALID_TEAM_CONTEXT', 'Team context must be PAC or CHARLIE.');
  }
  return team;
}

function resolveTeamContext(auth, requestedContext) {
  const context = getRoleContext(auth?.role);
  const requested = normalizeTeamContext(requestedContext);
  if (!context.allowedTeams.length) {
    throw tenancyError(403, 'ERR_TEAM_ACCESS_DENIED', 'Role cannot access team filter data.');
  }
  if (!context.canSwitchTeam) {
    if (requested && requested !== context.assignedTeam) {
      throw tenancyError(403, 'ERR_TEAM_ACCESS_DENIED', 'Role cannot access requested team.');
    }
    return context.assignedTeam;
  }
  if (!requested) {
    throw tenancyError(400, 'ERR_TEAM_CONTEXT_REQUIRED', 'X-Team-Context is required for this role.');
  }
  if (!context.allowedTeams.includes(requested)) {
    throw tenancyError(403, 'ERR_TEAM_ACCESS_DENIED', 'Role cannot access requested team.');
  }
  return requested;
}

module.exports = { TEAM_CONTEXT, getRoleContext, normalizeTeamContext, resolveTeamContext };
