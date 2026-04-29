-- Run in Supabase SQL Editor (public schema).
-- Adds threat-intel correlation fields to vt_ip_cache.

alter table public.vt_ip_cache
  add column if not exists corr_confidence int,
  add column if not exists corr_payload jsonb not null default '{}'::jsonb;

create index if not exists vt_ip_cache_corr_confidence_idx
  on public.vt_ip_cache (corr_confidence);

comment on column public.vt_ip_cache.corr_confidence is 'Correlation confidence score (0-100) from /api/correlate.';
comment on column public.vt_ip_cache.corr_payload is 'Full correlation payload (sources verdicts + meta).';

