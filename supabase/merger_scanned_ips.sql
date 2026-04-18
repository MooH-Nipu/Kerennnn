-- Run in Supabase SQL Editor (public schema).
-- Stores IPs + JSON payload for the "Merger (DB)" tab.

create table if not exists public.merger_scanned_ips (
  ip text primary key,
  payload jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create index if not exists merger_scanned_ips_updated_at_idx
  on public.merger_scanned_ips (updated_at desc);

comment on table public.merger_scanned_ips is 'Manual scan rows for JSON Merger (DB) — synced to SIEM query.terms output.';
