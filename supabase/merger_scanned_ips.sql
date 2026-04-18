-- Run in Supabase SQL Editor (public schema).
-- Stores IPs + JSON payload for the PAC Filter tab.

-- Satu baris per IP: PRIMARY KEY mencegah duplikat (bentrok insert/upsert = update baris yang sama).
-- updated_at: timestamptz. Aplikasi mengisi dengan offset WIB (+07:00). Default now() untuk insert manual dari SQL.
create table if not exists public.merger_scanned_ips (
  ip text primary key,
  payload jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create index if not exists merger_scanned_ips_updated_at_idx
  on public.merger_scanned_ips (updated_at desc);

comment on table public.merger_scanned_ips is 'Manual scan rows for PAC Filter — synced to SIEM query.terms output.';
