-- Safe additive migration for per-user navigation visibility and display labels.
-- Run this in Supabase SQL Editor before deploying the matching application code.

alter table public.user_prefs
  add column if not exists tab_labels jsonb not null default '{}'::jsonb;

alter table public.user_prefs
  add column if not exists group_labels jsonb not null default '{}'::jsonb;

comment on column public.user_prefs.tab_labels is
  'Per-user display labels keyed by stable tab id.';

comment on column public.user_prefs.group_labels is
  'Per-user display labels keyed by stable navigation group id.';

-- tab_order is intentionally retained during rollout for compatibility.
-- Drop it later, after every deployed client no longer reads or writes it:
-- alter table public.user_prefs drop column if exists tab_order;
