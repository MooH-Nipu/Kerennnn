'use strict';

/**
 * Log the full error server-side and return a generic message to the client.
 * Prevents leaking Supabase/Postgres schema details (table/column names,
 * constraint info) through raw `error.message` in 500 responses.
 */
function serverError(res, err, context = '') {
  const detail = err && err.message ? err.message : String(err);
  console.error(`[api]${context ? ' ' + context : ''}:`, detail);
  return res.status(500).json({ error: 'Internal server error.' });
}

module.exports = { serverError };
