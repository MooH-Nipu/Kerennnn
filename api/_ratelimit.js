'use strict';

const MAX_ATTEMPTS = Number.parseInt(process.env.LOGIN_MAX_ATTEMPTS, 10) || 10;
const WINDOW_MIN = Number.parseInt(process.env.LOGIN_WINDOW_MINUTES, 10) || 15;
const WINDOW_MS = WINDOW_MIN * 60 * 1000;
const localAttempts = new Map();

function getClientIp(req) {
  return String(
    req.trustedClientIp || req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || 'unknown'
  );
}

function consumeLocalIpBudget(ip, now = Date.now()) {
  if (localAttempts.size > 1000) {
    for (const [key, entry] of localAttempts) if (now >= entry.resetAt) localAttempts.delete(key);
  }
  const current = localAttempts.get(ip);
  const entry = !current || now >= current.resetAt ? { count: 0, resetAt: now + WINDOW_MS } : current;
  const locked = entry.count >= MAX_ATTEMPTS;
  if (!locked) entry.count += 1;
  localAttempts.set(ip, entry);
  return { locked, remaining: Math.max(0, MAX_ATTEMPTS - entry.count) };
}

async function checkLoginRateLimit(supabase, username, ip) {
  const local = consumeLocalIpBudget(ip);
  if (local.locked || !supabase) return local;
  try {
    const sinceIso = new Date(Date.now() - WINDOW_MS).toISOString();
    const { count, error } = await supabase
      .from('login_attempts')
      .select('id', { count: 'exact', head: true })
      .eq('username', username)
      .eq('ip', ip)
      .eq('success', false)
      .gt('attempted_at', sinceIso);
    if (error) return local;
    const fails = count || 0;
    return { locked: fails >= MAX_ATTEMPTS, remaining: Math.min(local.remaining, Math.max(0, MAX_ATTEMPTS - fails)) };
  } catch {
    return local;
  }
}

async function recordLoginAttempt(supabase, username, ip, success) {
  if (!supabase) return;
  try {
    await supabase.from('login_attempts').insert({ username, ip, success: !!success });
  } catch {
    /* local IP budget remains active when persistence fails */
  }
}

function resetLocalRateLimitForTest() {
  localAttempts.clear();
}

module.exports = {
  getClientIp,
  checkLoginRateLimit,
  recordLoginAttempt,
  resetLocalRateLimitForTest,
  MAX_ATTEMPTS,
  WINDOW_MIN,
};
