-- Run in Supabase SQL Editor (public schema).
-- Per-user external API consumption log (api/_usage.js). Powers the admin
-- "API Usage" tab (api/admin/usage.js). Best-effort telemetry: insert failures
-- never block or fail a scan. Scoped reads are admin-only via the API.

create table if not exists public.api_usage (
  id         bigint generated always as identity primary key,
  user_id    uuid,
  username   text,
  service    text not null,                 -- VirusTotal | AbuseIPDB | AlienVault OTX | Abuse.ch | URLScan.io | Enrichment | NVD | ATT&CK | Passive DNS | crt.sh
  ioc_type   text,                          -- ip | domain | hash | null
  outcome    text not null default 'ok',    -- ok | rate_limited | error
  api_key    text,                          -- short, non-secret key prefix of whichever TI source served the call (any source, not just VT)
  created_at timestamptz not null default now()
);

-- If you previously created this table with a `vt_key` column, migrate it:
--   alter table public.api_usage rename column vt_key to api_key;

create index if not exists api_usage_created_idx on public.api_usage (created_at desc);
create index if not exists api_usage_user_idx    on public.api_usage (user_id, created_at desc);
create index if not exists api_usage_service_idx on public.api_usage (service);

comment on table public.api_usage is
  'Per-user external API call log (api/_usage.js): service, ioc_type, outcome, api_key (key prefix of whichever TI source served the call). Powers the admin API Usage tab.';
