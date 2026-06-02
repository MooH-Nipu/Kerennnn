'use strict';

/**
 * Best-effort admin audit logging. Writes one row to public.audit_log.
 * Never throws — auditing must not block or fail the primary admin action.
 *
 * entry: { actorId, actorUsername, action, target, detail }
 */
async function writeAudit(supabase, entry) {
  if (!supabase || !entry || !entry.action) return;
  try {
    await supabase.from('audit_log').insert({
      actor_id: entry.actorId || null,
      actor_username: entry.actorUsername || null,
      action: entry.action,
      target: entry.target || null,
      detail: entry.detail || null,
    });
  } catch {
    /* best-effort: swallow audit failures */
  }
}

module.exports = { writeAudit };
