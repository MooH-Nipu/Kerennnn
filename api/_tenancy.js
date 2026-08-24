'use strict';

function tenancyError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function getRoleContext(role, teamAccess) {
  const explicit = Array.isArray(teamAccess)
    ? teamAccess.map(value => String(value).trim().toUpperCase()).filter(value => value === 'PAC' || value === 'CHARLIE')
    : [];
  const allowedTeams = ['PAC', 'CHARLIE'].filter(team => explicit.includes(team));
  return {
    assignedTeam: allowedTeams.length === 1 ? allowedTeams[0] : null,
    allowedTeams,
    canSwitchTeam: allowedTeams.length > 1,
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
  const context = getRoleContext(auth?.role, auth?.teamAccess);
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

module.exports = { getRoleContext, normalizeTeamContext, resolveTeamContext };
