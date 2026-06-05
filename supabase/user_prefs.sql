-- Run in Supabase SQL Editor (public schema).
-- Per-user UI preferences (api/user-prefs.js). Currently backs the customizable
-- tab bar: `tab_order` is the user's preferred tab ordering, `hidden_tabs` are
-- tab ids they have hidden. Both are arrays of tab-id strings (see TabId in
-- src/lib/permissions.ts). Scope is strictly per-user: every read/write is
-- filtered by user_id — the API is the only trust boundary (service-role key
-- bypasses RLS). One row per user (upsert on user_id).

create table if not exists public.user_prefs (
  user_id     uuid primary key,
  tab_order   jsonb not null default '[]'::jsonb,
  hidden_tabs jsonb not null default '[]'::jsonb,
  updated_at  timestamptz not null default now()
);

comment on table public.user_prefs is 'Per-user UI prefs (api/user-prefs.js): customizable tab order + hidden tabs. Always scoped by user_id.';
comment on column public.user_prefs.tab_order is 'Ordered array of tab-id strings (TabId in src/lib/permissions.ts). Empty = default order.';
comment on column public.user_prefs.hidden_tabs is 'Array of tab-id strings the user has hidden from their nav.';
