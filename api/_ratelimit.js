'use strict';

const MAX_ATTEMPTS = Number.parseInt(process.env.LOGIN_MAX_ATTEMPTS, 10) || 5;
const WINDOW_MIN = Number.parseInt(process.env.LOGIN_WINDOW_MINUTES, 10) || 15;

/** Best-effort client IP extraction (honours the proxy X-Forwarded-For header). */
function getClientIp(req) {
  const xff = req.headers && req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) return xff.split(',')[0].trim();
  return (
    (req.socket && req.socket.remoteAddress) ||
    (req.connection && req.connection.remoteAddress) ||
    'unknown'
  );
}

/**
 * Counts recent FAILED attempts for (username, ip) within the lockout window.
 * Returns { locked, remaining }. Best-effort: never throws, fails open if the
 * login_attempts table is missing or Supabase is unconfigured.
 */
async function checkLoginRateLimit(supabase, username, ip) {
  if (!supabase) return { locked: false, remaining: MAX_ATTEMPTS };
  try {
    const sinceIso = new Date(Date.now() - WINDOW_MIN * 60 * 1000).toISOString();
    const { count } = await supabase
      .from('login_attempts')
      .select('id', { count: 'exact', head: true })
      .eq('username', username)
      .eq('ip', ip)
      .eq('success', false)
      .gt('attempted_at', sinceIso);
    const fails = count || 0;
    return { locked: fails >= MAX_ATTEMPTS, remaining: Math.max(0, MAX_ATTEMPTS - fails) };
  } catch {
    return { locked: false, remaining: MAX_ATTEMPTS };
  }
}

/** Records one login attempt (success or failure). Best-effort: never throws. */
async function recordLoginAttempt(supabase, username, ip, success) {
  if (!supabase) return;
  try {
    await supabase.from('login_attempts').insert({ username, ip, success: !!success });
  } catch {
    /* best-effort */
  }
}

module.exports = {
  getClientIp,
  checkLoginRateLimit,
  recordLoginAttempt,
  MAX_ATTEMPTS,
  WINDOW_MIN,
};
