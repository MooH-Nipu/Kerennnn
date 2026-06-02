-- Run in Supabase SQL Editor (public schema).
-- Per-user IoC scan history for the Riwayat Scan tab (api/scan-history.js).
-- Replaces the previous browser-localStorage history (per-browser, capped at 20).
-- Scope is strictly per-user: every read/write is filtered by user_id (admins
-- included) — the API is the only trust boundary (service-role key bypasses RLS).

create table if not exists public.scan_history (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null,
  username    text,
  input       text not null,
  count       int  not null default 0,
  items       jsonb not null default '[]'::jsonb,
  created_at  timestamptz not null default now()
);

create index if not exists scan_history_user_created_idx
  on public.scan_history (user_id, created_at desc);

comment on table public.scan_history is 'Per-user IoC scan history (api/scan-history.js): input, count, items snapshot. Always scoped by user_id.';
