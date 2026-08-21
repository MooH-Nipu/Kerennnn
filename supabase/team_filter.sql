-- Kerennnn multi-team filter migration (additive and idempotent).
-- Run once in Supabase SQL Editor before enabling Team Filter users.

begin;

create extension if not exists pgcrypto;

-- Extend existing app_users role check without dropping data.
alter table public.app_users drop constraint if exists app_users_role_check;
alter table public.app_users
  add constraint app_users_role_check
  check (role in ('admin', 'soc_lead', 'pac', 'charlie', 'l1', 'l2'));

create table if not exists public.team_filter_ips (
  team text not null check (team in ('PAC', 'CHARLIE')),
  ip inet not null,
  payload jsonb not null default '{}'::jsonb,
  updated_by uuid references public.app_users(id) on delete set null,
  updated_at timestamptz not null default now(),
  primary key (team, ip),
  check (family(ip) = 4)
);

create index if not exists team_filter_ips_team_updated_idx
  on public.team_filter_ips (team, updated_at desc);

create table if not exists public.team_filter_audit (
  id bigint generated always as identity primary key,
  request_id text not null unique,
  actor_id uuid references public.app_users(id) on delete set null,
  actor_username text not null,
  team text not null check (team in ('PAC', 'CHARLIE')),
  operation text not null check (operation in ('list', 'insert', 'delete')),
  item_count integer not null default 0 check (item_count >= 0),
  execution_time_ms integer not null check (execution_time_ms >= 0),
  status text not null check (status in ('ok', 'denied', 'error')),
  detail jsonb,
  created_at timestamptz not null default now()
);

create index if not exists team_filter_audit_team_created_idx
  on public.team_filter_audit (team, created_at desc);
create index if not exists team_filter_audit_actor_created_idx
  on public.team_filter_audit (actor_id, created_at desc);

create or replace function public.sync_legacy_pac_filter()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if tg_op = 'DELETE' then
    if old.ip ~ '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$' then
      delete from public.team_filter_ips where team = 'PAC' and ip = old.ip::inet;
    end if;
    return old;
  end if;
  if tg_op = 'UPDATE' and old.ip is distinct from new.ip then
    if old.ip ~ '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$' then
      delete from public.team_filter_ips where team = 'PAC' and ip = old.ip::inet;
    end if;
  end if;
  if new.ip !~ '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$' then return new; end if;
  insert into public.team_filter_ips (team, ip, payload, updated_at)
  values ('PAC', new.ip::inet, new.payload, new.updated_at)
  on conflict (team, ip) do update
    set payload = excluded.payload, updated_at = excluded.updated_at;
  return new;
end;
$$;

drop trigger if exists merger_scanned_ips_team_bridge on public.merger_scanned_ips;
create trigger merger_scanned_ips_team_bridge
after insert or update or delete on public.merger_scanned_ips
for each row execute function public.sync_legacy_pac_filter();

create or replace function public.mutate_team_filter(
  p_team text,
  p_operation text,
  p_ips text[],
  p_actor_id uuid,
  p_actor_username text,
  p_request_id text,
  p_execution_time_ms integer
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  actor_role text;
  actor_username text;
  changed text[] := array[]::text[];
  requested_count integer := coalesce(array_length(p_ips, 1), 0);
begin
  select role, username into actor_role, actor_username from public.app_users where id = p_actor_id;
  if actor_role is null then raise exception 'current account not found' using errcode = '42501'; end if;
  if p_team not in ('PAC', 'CHARLIE') or p_operation not in ('insert', 'delete') then
    raise exception 'invalid team filter mutation' using errcode = '22023';
  end if;
  if not (
    (actor_role = 'pac' and p_team = 'PAC') or
    (actor_role = 'charlie' and p_team = 'CHARLIE') or
    actor_role in ('admin', 'soc_lead', 'l2')
  ) then raise exception 'team access denied' using errcode = '42501'; end if;

  if p_operation = 'insert' then
    with inserted as (
      insert into public.team_filter_ips (team, ip, payload, updated_by)
      select p_team, value::inet, jsonb_build_object('ioc', value), p_actor_id
      from unnest(p_ips) value
      on conflict (team, ip) do nothing
      returning host(ip) as ip
    ) select coalesce(array_agg(ip), array[]::text[]) into changed from inserted;

    if p_team = 'PAC' and cardinality(changed) > 0 then
      insert into public.merger_scanned_ips (ip, payload, updated_at)
      select value, jsonb_build_object('ioc', value), now() from unnest(changed) value
      on conflict (ip) do nothing;
    end if;
  else
    with deleted as (
      delete from public.team_filter_ips
      where team = p_team and ip = any(p_ips::inet[])
      returning host(ip) as ip
    ) select coalesce(array_agg(ip), array[]::text[]) into changed from deleted;

    if p_team = 'PAC' and cardinality(changed) > 0 then
      delete from public.merger_scanned_ips where ip = any(changed);
    end if;
  end if;

  insert into public.team_filter_audit (
    request_id, actor_id, actor_username, team, operation,
    item_count, execution_time_ms, status, detail
  ) values (
    p_request_id, p_actor_id, actor_username, p_team, p_operation,
    cardinality(changed), greatest(p_execution_time_ms, 0), 'ok',
    jsonb_build_object('requested', requested_count, 'skipped', requested_count - cardinality(changed))
  );

  return jsonb_build_object(
    'ips', to_jsonb(changed),
    'changed_count', cardinality(changed),
    'skipped_count', requested_count - cardinality(changed)
  );
end;
$$;

revoke all on function public.sync_legacy_pac_filter() from public, anon, authenticated;
revoke all on function public.mutate_team_filter(text, text, text[], uuid, text, text, integer) from public, anon, authenticated;
grant execute on function public.mutate_team_filter(text, text, text[], uuid, text, text, integer) to service_role;

-- Preserve current PAC list as PAC data. Conflict-safe on repeated runs.
with valid_legacy_ips as materialized (
  select ip, payload, updated_at
  from public.merger_scanned_ips
  where ip ~ '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
)
insert into public.team_filter_ips (team, ip, payload, updated_at)
select 'PAC', ip::inet, payload, updated_at
from valid_legacy_ips
on conflict (team, ip) do nothing;

-- Browser clients have no direct table access. Server uses service-role key.
alter table public.team_filter_ips enable row level security;
alter table public.team_filter_audit enable row level security;
revoke all on public.team_filter_ips from anon, authenticated;
revoke all on public.team_filter_audit from anon, authenticated;
revoke all on sequence public.team_filter_audit_id_seq from anon, authenticated;

comment on table public.team_filter_ips is 'Team-isolated PAC/Charlie IPv4 lists used to generate SIEM terms templates.';
comment on table public.team_filter_audit is 'Append-only server-side audit of team filter list/insert/delete operations.';

commit;
