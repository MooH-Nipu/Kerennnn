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
  vt_key     text,                          -- VirusTotal key prefix (VT only), else null
  created_at timestamptz not null default now()
);

create index if not exists api_usage_created_idx on public.api_usage (created_at desc);
create index if not exists api_usage_user_idx    on public.api_usage (user_id, created_at desc);
create index if not exists api_usage_service_idx on public.api_usage (service);

comment on table public.api_usage is
  'Per-user external API call log (api/_usage.js): service, ioc_type, outcome, vt_key. Powers the admin API Usage tab.';
