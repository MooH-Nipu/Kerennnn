-- Run in Supabase SQL Editor (public schema).
-- Append-only admin audit trail for user management
-- (create / update / delete / role change) written by api/admin/users.js.

create table if not exists public.audit_log (
  id             uuid primary key default gen_random_uuid(),
  actor_id       uuid,
  actor_username text,
  action         text not null,
  target         text,
  detail         jsonb,
  created_at     timestamptz not null default now()
);

create index if not exists audit_log_created_at_idx
  on public.audit_log (created_at desc);

comment on table public.audit_log is 'Append-only admin action audit (api/admin/users.js): actor, action, target, detail.';
