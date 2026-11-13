'use strict';
const { getSupabase } = require('../_supabase');
const { requireApiKey } = require('../_apikeys');
const { readJsonBody } = require('../_auth');
const { invokeJson } = require('../_internal-invoke');
const { scanBatch, MAX_BATCH } = require('../_v1-scan-core');
const vtHandler = require('../vt');
const correlateHandler = require('../correlate');

function jsonError(res, status, code, message) {
  return res.status(status).json({ ok: false, error: { code, message } });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, X-API-Key, Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return jsonError(res, 405, 'METHOD_NOT_ALLOWED', 'Use POST.');

  const supabase = getSupabase();
  if (!await requireApiKey(req, res, supabase, 'ioc:scan')) return;

  const body = await readJsonBody(req).catch(() => null);
  const input = Array.isArray(body?.iocs) ? body.iocs : (body?.ioc ? [body.ioc] : []);
  if (!input.length) return jsonError(res, 400, 'NO_IOCS', 'Send {"iocs":["8.8.8.8"]}.');
  if (input.length > MAX_BATCH) return jsonError(res, 400, 'BATCH_TOO_LARGE', `Max ${MAX_BATCH} IOCs per request.`);

  const { results, errors } = await scanBatch({
    rawIocs: input,
    allowedTypes: req.apiKey.allowedTypes,
    auth: req.auth,
    invoke: invokeJson,
    vtHandler,
    correlateHandler,
  });

  return res.status(200).json({
    ok: true,
    key: { prefix: req.apiKey.prefix, scopes: req.apiKey.scopes, allowedTypes: req.apiKey.allowedTypes },
    count: results.length,
    results,
    errors,
  });
};
