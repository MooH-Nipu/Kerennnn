'use strict';

/** Minimal express-like response recorder for handler tests. */
function fakeRes() {
  const headers = {};
  const res = {
    statusCode: 200,
    body: undefined,
    headers,
    setHeader(name, value) { headers[String(name).toLowerCase()] = value; return res; },
    getHeader(name) { return headers[String(name).toLowerCase()]; },
    status(code) { res.statusCode = code; return res; },
    json(value) { res.body = value; return res; },
    send(value) { res.body = value; return res; },
    end(value) { if (value !== undefined) res.body = value; return res; },
  };
  return res;
}

function fakeReq({ method = 'GET', query = {}, body = undefined, headers = {} } = {}) {
  return { method, query, body, headers, socket: { remoteAddress: '127.0.0.1' }, trustedClientIp: '127.0.0.1' };
}

/** Supabase stub: one canned row per table, chainable chain, never hits network. */
function fakeSupabase(rowsByTable = {}, { insertResult = { data: null, error: null }, updateError = null } = {}) {
  return {
    from(table) {
      const result = () => ({ data: rowsByTable[table] ?? null, error: null });
      const builder = {
        select() { return builder; },
        eq() { return builder; },
        is() { return builder; },
        update() { return builder; },
        insert() { return Promise.resolve(insertResult); },
        maybeSingle: async () => result(),
        then: (resolve, reject) => Promise.resolve(updateError ? { data: null, error: updateError } : { data: null, error: null }).then(resolve, reject),
      };
      return builder;
    },
  };
}

module.exports = { fakeReq, fakeRes, fakeSupabase };
