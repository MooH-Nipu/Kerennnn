-- Run in Supabase SQL Editor (public schema).
-- Per-user API keys for the public scan API (api/_apikeys.js, api/api-keys.js, api/v1/*).
-- A user may hold several live keys (one per integration); each key carries its own ACL.
-- Only sha256(key) is stored; the plaintext key is shown once at creation.

create table if not exists public.api_keys (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null,
  username      text,
  label         text,
  key_prefix    text not null,
  key_hash      text not null unique,
  scopes        text[] not null default array['ioc:scan', 'ioc:read']::text[],
  allowed_types text[] not null default array['ip', 'domain', 'hash']::text[],
  enabled       boolean not null default true,
  last_used_at  timestamptz,
  created_at    timestamptz not null default now(),
  revoked_at    timestamptz
);

-- Listing a user's live keys; deliberately NOT unique — multiple keys per user is supported.
create index if not exists api_keys_user_live_idx
  on public.api_keys (user_id) where revoked_at is null;

create index if not exists api_keys_hash_lookup_idx
  on public.api_keys (key_hash) where revoked_at is null;

comment on table public.api_keys is
  'Per-user API keys for /api/v1 (api/_apikeys.js). Stores key_hash only. Multiple live keys per user, one per integration.';
