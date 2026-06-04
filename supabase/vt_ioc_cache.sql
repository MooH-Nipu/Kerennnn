-- Run in Supabase SQL Editor (public schema).
-- Generic cache for VT domain + hash scans (parallel to vt_ip_cache which stays
-- IP-only for the recent-list / seen-before / TTL behavior). This table backs the
-- "Analisa Mendalam" deep-analysis page for non-IP IOCs.
-- TTL is enforced by API lazy cleanup (delete rows older than 15 days by first_scanned_at).

create extension if not exists pgcrypto; -- gen_random_uuid()

create table if not exists public.vt_ioc_cache (
  id uuid unique not null default gen_random_uuid(),
  ioc text not null,
  ioc_type text not null check (ioc_type in ('ip', 'domain', 'hash')),
  scan_count int not null default 0,
  first_scanned_at timestamptz not null default now(),
  last_scanned_at timestamptz not null default now(),
  vt_verdict text,
  vt_stats jsonb not null default '{}'::jsonb,
  vt_payload jsonb not null default '{}'::jsonb,
  corr_confidence int,
  corr_payload jsonb not null default '{}'::jsonb,
  primary key (ioc_type, ioc)
);

create index if not exists vt_ioc_cache_id_idx
  on public.vt_ioc_cache (id);

create index if not exists vt_ioc_cache_last_scanned_at_idx
  on public.vt_ioc_cache (last_scanned_at desc);

comment on table public.vt_ioc_cache is 'Cache for VT domain/hash scans (deep-analysis link target + correlation payload). TTL: 15 days from first_scanned_at, via API cleanup.';
comment on column public.vt_ioc_cache.id is 'Stable identifier per IOC row (link target for /result/<id>).';
comment on column public.vt_ioc_cache.corr_confidence is 'Correlation confidence score (0-100) from /api/correlate.';
comment on column public.vt_ioc_cache.corr_payload is 'Full correlation payload (sources verdicts + meta + risk factors).';
