-- Run in Supabase SQL Editor (public schema).
-- Per-user MALICIOUS alert webhook config (api/user-webhook.js + api/correlate.js).
-- Each user sets their own Slack / Teams / Discord (or generic JSON) webhook URL;
-- correlate.js fires it when a scan's confidence >= min_confidence.
-- Scope is strictly per-user: every read/write is filtered by user_id.

create table if not exists public.user_webhooks (
  user_id        uuid primary key,
  username       text,
  webhook_url    text,
  enabled        boolean not null default true,
  min_confidence int not null default 70,
  updated_at     timestamptz not null default now()
);

comment on table public.user_webhooks is
  'Per-user alert webhook (api/user-webhook.js). correlate.js fires the user''s webhook when scan confidence >= min_confidence.';
