-- Run in Supabase SQL Editor (public schema).
-- One row per user-initiated IP lookup, including cache hits.

create table if not exists public.ip_scan_events (
  id         bigint generated always as identity primary key,
  user_id    uuid,
  username   text,
  ip         text not null,
  created_at timestamptz not null default now()
);

create index if not exists ip_scan_events_created_idx
  on public.ip_scan_events (created_at desc);

comment on table public.ip_scan_events is
  'User-attributed IP lookup events. Includes VirusTotal cache hits and powers dashboard IP scans per user.';
