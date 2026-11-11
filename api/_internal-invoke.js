'use strict';

/**
 * Calls an existing API handler in-process and captures its JSON response.
 *
 * Why: the public API must return exactly what the browser sees — same caches,
 * same VT key rotation, same scan budgets, same telemetry, same webhook alerts.
 * Re-implementing that pipeline would drift. The caller injects an already
 * authenticated req.auth, so requireAuth() short-circuits.
 */
async function invokeJson(handler, { method = 'GET', query = {}, body, auth } = {}) {
  const headers = {};
  let statusCode = 200;
  let payload;
  let ended = false;

  const req = {
    method,
    query,
    body,
    headers: { 'content-type': 'application/json' },
    auth,
    authCurrent: true,
    socket: { remoteAddress: '127.0.0.1' },
    trustedClientIp: '127.0.0.1',
  };

  const res = {
    statusCode: 200,
    get headersSent() { return ended; },
    setHeader(name, value) { headers[String(name).toLowerCase()] = value; return res; },
    getHeader(name) { return headers[String(name).toLowerCase()]; },
    status(code) { statusCode = code; res.statusCode = code; return res; },
    json(value) { payload = value; ended = true; return res; },
    send(value) { payload = value; ended = true; return res; },
    end(value) { if (value !== undefined) payload = value; ended = true; return res; },
  };

  await handler(req, res);

  if (typeof payload === 'string') {
    try { payload = JSON.parse(payload); } catch { /* leave as text */ }
  }
  return { status: statusCode, body: payload, headers };
}

module.exports = { invokeJson };
