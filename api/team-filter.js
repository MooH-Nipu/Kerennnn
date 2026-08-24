'use strict';

const crypto = require('crypto');
const net = require('net');
const { normalizeIpLine } = require('./_ioc');
const { requireCurrentRole, readJsonBody } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { resolveTeamContext } = require('./_tenancy');

const MAX_BATCH = 1000;
const PAGE_SIZE = 1000;
const ALLOWED_METHODS = new Set(['GET', 'POST', 'DELETE']);
const CLIENT_CODE_RE = /^[A-Z0-9_-]{2,32}$/;

function normalizeClientCode(value) {
  if (typeof value !== 'string') throw boundaryError('Client context is required.');
  const code = value.trim().toUpperCase();
  if (!CLIENT_CODE_RE.test(code)) throw boundaryError('Client code must be 2-32 characters: A-Z, 0-9, underscore, or hyphen.');
  return code;
}

function isAllowedMethod(method) {
  return ALLOWED_METHODS.has(method);
}

function operationForMethod(method) {
  return method === 'GET' ? 'list' : method === 'POST' ? 'insert' : 'delete';
}

function requestId() {
  return `req_${crypto.randomBytes(12).toString('hex')}`;
}

function boundaryError(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}

function sanitizeFilterItems(items) {
  if (!Array.isArray(items) || items.length === 0) throw boundaryError('Body must contain at least one item.');
  if (items.length > MAX_BATCH) throw boundaryError(`Batch maximum ${MAX_BATCH} items.`);
  const unique = new Set();
  for (const row of items) {
    const raw = row && typeof row === 'object' ? row.ip ?? row.ioc : row;
    const ip = normalizeIpLine(raw == null ? '' : String(raw));
    if (!ip || net.isIP(ip) !== 4) throw boundaryError('Every item must contain a valid IPv4 address.');
    unique.add(ip);
  }
  return [...unique].map(ip => ({ ip, payload: { ioc: ip } }));
}

function sanitizeDeleteIps(values) {
  return sanitizeFilterItems((Array.isArray(values) ? values : []).map(ip => ({ ip }))).map(row => row.ip);
}

function isSchemaMissingError(error) {
  return ['42P01', 'PGRST204', 'PGRST205'].includes(String(error?.code || ''));
}

function sendError(res, status, code, message, id) {
  return res.status(status).json({ success: false, error_code: code, message, request_id: id });
}

async function recordTeamFilterEvent(supabase, req, id, started, event) {
  const { error } = await supabase.rpc('record_team_filter_event', {
    p_actor_id: req.auth.userId,
    p_request_id: id,
    p_team: event.team || null,
    p_operation: event.operation,
    p_status: event.status,
    p_item_count: event.itemCount || 0,
    p_execution_time_ms: Date.now() - started,
    p_detail: event.detail || null,
  });
  if (error) console.error('[team-filter audit]', error.code || 'error');
  return !error;
}

async function auditThenError(supabase, req, res, id, started, event, response) {
  const auditOk = await recordTeamFilterEvent(supabase, req, id, started, event);
  if (!auditOk) return sendError(res, 503, 'ERR_AUDIT_UNAVAILABLE', 'Request failed and audit persistence was unavailable.', id);
  return sendError(res, response.status, response.code, response.message, id);
}

async function fetchAllTeamFilterRows(supabase, team) {
  const items = [];
  for (let from = 0; ; from += PAGE_SIZE) {
    const { data, error } = await supabase
      .from('team_filter_ips')
      .select('ip,payload,updated_at')
      .eq('team', team)
      .order('ip', { ascending: true })
      .range(from, from + PAGE_SIZE - 1);
    if (error) return { items, error };
    const rows = data || [];
    items.push(...rows);
    if (rows.length < PAGE_SIZE) return { items, error: null };
  }
}

async function resolveCharlieClient(supabase, code) {
  const { data, error } = await supabase
    .from('charlie_filter_clients')
    .select('id,code,label')
    .eq('code', code)
    .eq('active', true)
    .maybeSingle();
  return { client: data || null, error };
}

async function fetchAllCharlieClientFilterRows(supabase, clientId) {
  const items = [];
  for (let from = 0; ; from += PAGE_SIZE) {
    const { data, error } = await supabase
      .from('charlie_client_filter_ips')
      .select('ip,payload,updated_at')
      .eq('client_id', clientId)
      .order('ip', { ascending: true })
      .range(from, from + PAGE_SIZE - 1);
    if (error) return { items, error };
    const rows = data || [];
    items.push(...rows);
    if (rows.length < PAGE_SIZE) return { items, error: null };
  }
}

module.exports = async function handler(req, res) {
  const id = requestId();
  const started = Date.now();
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Team-Context, X-Client-Context');
  res.setHeader('X-Request-Id', id);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!isAllowedMethod(req.method)) {
    res.setHeader('Allow', 'GET, POST, DELETE, OPTIONS');
    return sendError(res, 405, 'ERR_METHOD_NOT_ALLOWED', 'Method not allowed.', id);
  }

  const supabase = getSupabase();
  if (!supabase) return sendError(res, 503, 'ERR_DATABASE_UNAVAILABLE', 'Supabase is not configured.', id);
  if (!await requireCurrentRole(req, res, supabase, ['admin', 'pac', 'charlie', 'soc_lead', 'l2'])) return;

  let team;
  try {
    team = resolveTeamContext(req.auth, req.headers['x-team-context']);
  } catch (error) {
    return auditThenError(supabase, req, res, id, started, {
      team: null, operation: operationForMethod(req.method), status: 'denied', detail: { code: error.code || 'ERR_TEAM_ACCESS_DENIED' },
    }, {
      status: error.status || 403, code: error.code || 'ERR_TEAM_ACCESS_DENIED', message: error.message,
    });
  }

  let clientCode = null;
  let charlieClient = null;
  const requestedClient = req.headers['x-client-context'];
  if (requestedClient != null && String(requestedClient).trim() !== '') {
    try { clientCode = normalizeClientCode(requestedClient); }
    catch (error) {
      return sendError(res, error.status || 400, 'ERR_INVALID_CLIENT_CONTEXT', error.message, id);
    }
    if (team !== 'CHARLIE') {
      return sendError(res, 400, 'ERR_INVALID_CLIENT_CONTEXT', 'Client context is available only for CHARLIE.', id);
    }
    if (clientCode !== 'GENERAL') {
      const resolved = await resolveCharlieClient(supabase, clientCode);
      if (resolved.error) {
        if (isSchemaMissingError(resolved.error)) return sendError(res, 503, 'ERR_CLIENT_SCHEMA_NOT_READY', 'Charlie client filters are not ready.', id);
        return sendError(res, 503, 'ERR_CLIENT_LOOKUP_FAILED', 'Unable to load Charlie client context.', id);
      }
      if (!resolved.client) return sendError(res, 404, 'ERR_CLIENT_NOT_FOUND', 'Charlie client not found or inactive.', id);
      charlieClient = resolved.client;
    }
  }

  try {
    if (req.method === 'GET') {
      const scoped = team === 'CHARLIE' && clientCode && clientCode !== 'GENERAL';
      const { items, error } = scoped
        ? await fetchAllCharlieClientFilterRows(supabase, charlieClient.id)
        : await fetchAllTeamFilterRows(supabase, team);
      if (error) {
        const schemaMissing = isSchemaMissingError(error);
        if (schemaMissing) return sendError(res, 503, 'ERR_SCHEMA_NOT_READY', 'Run required Supabase migrations before using team filters.', id);
        return auditThenError(supabase, req, res, id, started, {
          team, operation: 'list', status: 'error', detail: { code: 'ERR_DATABASE' },
        }, { status: 500, code: 'ERR_INTERNAL', message: 'Internal server error.' });
      }
      const auditOk = await recordTeamFilterEvent(supabase, req, id, started, {
        team, operation: 'list', itemCount: items.length, status: 'ok',
        detail: clientCode ? { client: clientCode } : null,
      });
      if (!auditOk) return sendError(res, 503, 'ERR_AUDIT_UNAVAILABLE', 'Query completed but audit persistence failed; result withheld.', id);
      return res.status(200).json({
        success: true, team_context: team, client_context: clientCode,
        items, total_records: items.length, request_id: id,
      });
    }

    let body;
    try { body = await readJsonBody(req); }
    catch {
      return auditThenError(supabase, req, res, id, started, {
        team, operation: operationForMethod(req.method), status: 'denied', detail: { code: 'ERR_INVALID_JSON' },
      }, { status: 400, code: 'ERR_INVALID_JSON', message: 'Invalid JSON body.' });
    }

    if (req.method === 'POST') {
      let clean;
      try { clean = sanitizeFilterItems(body?.items); }
      catch (error) {
        return auditThenError(supabase, req, res, id, started, {
          team, operation: 'insert', status: 'denied', detail: { code: 'ERR_INVALID_FILTER_ITEMS' },
        }, { status: error.status || 400, code: 'ERR_INVALID_FILTER_ITEMS', message: error.message });
      }
      const ips = clean.map(row => row.ip);
      let mutation;
      if (team === 'CHARLIE' && clientCode && clientCode !== 'GENERAL') {
        mutation = await supabase.rpc('mutate_charlie_client_filter', {
          p_client_id: charlieClient.id, p_operation: 'insert', p_ips: ips,
          p_actor_id: req.auth.userId, p_actor_username: req.auth.username,
          p_request_id: id, p_execution_time_ms: Date.now() - started,
        });
      } else {
        mutation = await supabase.rpc('mutate_team_filter', {
          p_team: team, p_operation: 'insert', p_ips: ips,
          p_actor_id: req.auth.userId, p_actor_username: req.auth.username,
          p_request_id: id, p_execution_time_ms: Date.now() - started,
        });
      }
      const { data, error } = mutation;
      if (error) {
        const schemaMissing = isSchemaMissingError(error) || error.code === 'PGRST202';
        if (schemaMissing) return sendError(res, 503, 'ERR_SCHEMA_NOT_READY', 'Run required Supabase migrations before using team filters.', id);
        return auditThenError(supabase, req, res, id, started, {
          team, operation: 'insert', status: 'error', itemCount: ips.length,
          detail: { code: 'ERR_DATABASE' },
        }, { status: 500, code: 'ERR_INTERNAL', message: 'Internal server error.' });
      }
      return res.status(200).json({ success: true, team_context: team, saved: data?.ips ?? [], skippedCount: data?.skipped_count ?? 0, request_id: id });
    }

    if (req.method === 'DELETE') {
      let ips;
      try { ips = sanitizeDeleteIps(body?.ips); }
      catch (error) {
        return auditThenError(supabase, req, res, id, started, {
          team, operation: 'delete', status: 'denied', detail: { code: 'ERR_INVALID_FILTER_ITEMS' },
        }, { status: error.status || 400, code: 'ERR_INVALID_FILTER_ITEMS', message: error.message });
      }
      let mutation;
      if (team === 'CHARLIE' && clientCode && clientCode !== 'GENERAL') {
        mutation = await supabase.rpc('mutate_charlie_client_filter', {
          p_client_id: charlieClient.id, p_operation: 'delete', p_ips: ips,
          p_actor_id: req.auth.userId, p_actor_username: req.auth.username,
          p_request_id: id, p_execution_time_ms: Date.now() - started,
        });
      } else {
        mutation = await supabase.rpc('mutate_team_filter', {
          p_team: team, p_operation: 'delete', p_ips: ips,
          p_actor_id: req.auth.userId, p_actor_username: req.auth.username,
          p_request_id: id, p_execution_time_ms: Date.now() - started,
        });
      }
      const { data, error } = mutation;
      if (error) {
        const schemaMissing = isSchemaMissingError(error) || error.code === 'PGRST202';
        if (schemaMissing) return sendError(res, 503, 'ERR_SCHEMA_NOT_READY', 'Run required Supabase migrations before using team filters.', id);
        return auditThenError(supabase, req, res, id, started, {
          team, operation: 'delete', status: 'error', itemCount: ips.length,
          detail: { code: 'ERR_DATABASE' },
        }, { status: 500, code: 'ERR_INTERNAL', message: 'Internal server error.' });
      }
      const deleted = data?.ips ?? [];
      return res.status(200).json({ success: true, team_context: team, deleted, deletedCount: data?.changed_count ?? deleted.length, request_id: id });
    }

    throw new Error('unreachable method dispatch');
  } catch {
    return auditThenError(supabase, req, res, id, started, {
      team, operation: operationForMethod(req.method), status: 'error', detail: { code: 'ERR_INTERNAL' },
    }, { status: 500, code: 'ERR_INTERNAL', message: 'Internal server error.' });
  }
};

module.exports.sanitizeFilterItems = sanitizeFilterItems;
module.exports.isSchemaMissingError = isSchemaMissingError;
module.exports.requestId = requestId;
module.exports.isAllowedMethod = isAllowedMethod;
module.exports.fetchAllTeamFilterRows = fetchAllTeamFilterRows;
module.exports.normalizeClientCode = normalizeClientCode;
module.exports.resolveCharlieClient = resolveCharlieClient;
module.exports.fetchAllCharlieClientFilterRows = fetchAllCharlieClientFilterRows;
