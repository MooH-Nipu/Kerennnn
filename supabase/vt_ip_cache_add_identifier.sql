-- Run in Supabase SQL Editor (public schema).
-- Adds stable identifier per IP row for result page linking.

-- gen_random_uuid() lives in pgcrypto on Supabase.
create extension if not exists pgcrypto;

alter table public.vt_ip_cache
  add column if not exists id uuid;

-- Backfill existing rows once.
update public.vt_ip_cache
  set id = gen_random_uuid()
  where id is null;

-- Enforce non-null + uniqueness.
alter table public.vt_ip_cache
  alter column id set not null,
  alter column id set default gen_random_uuid();

create unique index if not exists vt_ip_cache_id_uidx
  on public.vt_ip_cache (id);

comment on column public.vt_ip_cache.id is 'Stable identifier per IP row (link target for /result/<id>).';

