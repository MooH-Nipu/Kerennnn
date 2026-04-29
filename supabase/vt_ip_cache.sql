-- Run in Supabase SQL Editor (public schema).
-- Stores cached VirusTotal scan metadata for IPs only.
-- TTL is enforced by API cleanup (delete rows older than 15 days by last_scanned_at).

create table if not exists public.vt_ip_cache (
  ip text primary key,
  scan_count int not null default 0,
  first_scanned_at timestamptz not null default now(),
  last_scanned_at timestamptz not null default now(),
  vt_verdict text,
  vt_stats jsonb not null default '{}'::jsonb,
  vt_payload jsonb not null default '{}'::jsonb
);

create index if not exists vt_ip_cache_last_scanned_at_idx
  on public.vt_ip_cache (last_scanned_at desc);

comment on table public.vt_ip_cache is 'Cache for VT IP scans (for seen-before + recent list). TTL: 15 days by API cleanup.';

