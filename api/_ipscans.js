'use strict';
const { getSupabase } = require('./_supabase');

// Scan attribution is separate from API-usage telemetry: a cache hit is still a user scan.
async function logIpScan(req, ip) {
  const supabase = getSupabase();
  if (!supabase || !ip) return;
  const auth = (req && req.auth) || {};
  try {
    await supabase.from('ip_scan_events').insert({
      user_id: auth.userId || null,
      username: auth.username || null,
      ip,
    });
  } catch {
    // Best-effort telemetry must not block an IP lookup.
  }
}

module.exports = { logIpScan };
