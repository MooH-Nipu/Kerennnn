-- Run in Supabase SQL Editor (public schema).
-- Brute-force protection for /api/auth/login. The API counts recent FAILED
-- attempts per (username, ip) within a window (LOGIN_WINDOW_MINUTES, default 15)
-- and rejects further tries with HTTP 429 once LOGIN_MAX_ATTEMPTS (default 10)
-- is reached.

create table if not exists public.login_attempts (
  id           uuid primary key default gen_random_uuid(),
  username     text not null,
  ip           text not null,
  success      boolean not null default false,
  attempted_at timestamptz not null default now()
);

create index if not exists login_attempts_lookup_idx
  on public.login_attempts (username, ip, attempted_at desc);

comment on table public.login_attempts is 'Login attempt log for brute-force rate limiting (api/auth/login.js). Rows older than the lockout window can be pruned safely.';
