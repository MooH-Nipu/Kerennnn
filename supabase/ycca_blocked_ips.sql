-- Run once in Supabase SQL Editor (Dashboard → SQL → New query).

create table if not exists public.ycca_blocked_ips (
  ip text primary key,
  created_at timestamptz not null default now()
);
