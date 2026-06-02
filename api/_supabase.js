'use strict';
const { createClient } = require('@supabase/supabase-js');

/**
 * Returns a configured Supabase service-role client, or null if the
 * SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY env vars are missing.
 *
 * The service-role key bypasses RLS — see README "Security / trust boundary".
 * This client must never be exposed to the browser.
 */
function getSupabase() {
  const url = process.env.SUPABASE_URL || '';
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  if (!url || !key) return null;
  return createClient(url, key);
}

module.exports = { getSupabase };
