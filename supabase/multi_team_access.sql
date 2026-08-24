-- Additive multi-team memberships for PAC/CHARLIE access.
-- Safe with the previous production app: existing role and RPC signatures remain valid.
begin;

alter table public.app_users
  add column if not exists team_access text[] not null default array[]::text[];

update public.app_users
set team_access = case
  when role = 'pac' then array['PAC']::text[]
  when role = 'charlie' then array['CHARLIE']::text[]
  when role in ('admin', 'soc_lead', 'l2') then array['PAC', 'CHARLIE']::text[]
  else team_access
end
where cardinality(team_access) = 0 and role in ('pac', 'charlie', 'admin', 'soc_lead', 'l2');

alter table public.app_users drop constraint if exists app_users_team_access_check;
alter table public.app_users add constraint app_users_team_access_check
  check (team_access <@ array['PAC', 'CHARLIE']::text[]);

create or replace function public.mutate_app_user_v2(
  p_actor_id uuid,
  p_operation text,
  p_target_id uuid default null,
  p_username text default null,
  p_password_hash text default null,
  p_role text default null,
  p_detail jsonb default null,
  p_team_access text[] default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  actor_role text;
  actor_username text;
  target public.app_users%rowtype;
  clean_team_access text[];
begin
  select role, username into actor_role, actor_username
  from public.app_users where id = p_actor_id;
  if actor_role is null or actor_role not in ('admin', 'l2') then
    raise exception 'admin access denied' using errcode = '42501';
  end if;
  if p_role is not null and p_role not in ('admin', 'soc_lead', 'l1', 'l2') then
    raise exception 'invalid role' using errcode = '22023';
  end if;
  if p_operation = 'update' then
    perform 1 from public.app_users where id = p_target_id;
    if not found then raise exception 'user not found' using errcode = 'P0002'; end if;
  end if;

  if p_team_access is not null then
    if exists (
      select 1 from unnest(p_team_access) value
      where upper(trim(value)) not in ('PAC', 'CHARLIE')
    ) then raise exception 'invalid team access' using errcode = '22023'; end if;
    select coalesce(array_agg(team order by team), array[]::text[])
    into clean_team_access
    from (select distinct upper(trim(value)) as team from unnest(p_team_access) value) normalized;
  end if;

  if p_operation = 'create' then
    insert into public.app_users (username, password_hash, role, team_access, created_by)
    values (
      p_username,
      p_password_hash,
      p_role,
      coalesce(clean_team_access, array[]::text[]),
      p_actor_id
    ) returning * into target;
  elsif p_operation = 'update' then
    update public.app_users set
      username = coalesce(p_username, username),
      password_hash = coalesce(p_password_hash, password_hash),
      role = coalesce(p_role, role),
      team_access = coalesce(clean_team_access, team_access)
    where id = p_target_id returning * into target;
    if target.id is null then raise exception 'user not found' using errcode = 'P0002'; end if;
  elsif p_operation = 'delete' then
    if p_target_id = p_actor_id then raise exception 'cannot delete own account' using errcode = '22023'; end if;
    select * into target from public.app_users where id = p_target_id;
    if target.id is null then raise exception 'user not found' using errcode = 'P0002'; end if;
    delete from public.app_users where id = p_target_id;
  else
    raise exception 'invalid user mutation' using errcode = '22023';
  end if;

  insert into public.audit_log (actor_id, actor_username, action, target, detail)
  values (
    p_actor_id,
    actor_username,
    'user.' || p_operation,
    target.username,
    coalesce(p_detail, '{}'::jsonb) || jsonb_build_object(
      'target_id', target.id,
      'role', target.role,
      'team_access', target.team_access
    )
  );
  return to_jsonb(target) - 'password_hash';
end;
$$;

-- Keep the previous production RPC signature safe during rolling deployment.
-- Legacy role edits map to exact memberships; new clients use mutate_app_user_v2.
create or replace function public.mutate_app_user(
  p_actor_id uuid,
  p_operation text,
  p_target_id uuid default null,
  p_username text default null,
  p_password_hash text default null,
  p_role text default null,
  p_detail jsonb default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  actor_role text;
  actor_username text;
  target public.app_users%rowtype;
  mapped_team_access text[];
begin
  select role, username into actor_role, actor_username
  from public.app_users where id = p_actor_id;
  if actor_role is null or actor_role not in ('admin', 'l2') then
    raise exception 'admin access denied' using errcode = '42501';
  end if;
  if p_role is not null and p_role not in ('admin', 'soc_lead', 'pac', 'charlie', 'l1', 'l2') then
    raise exception 'invalid role' using errcode = '22023';
  end if;
  mapped_team_access := case p_role
    when 'pac' then array['PAC']::text[]
    when 'charlie' then array['CHARLIE']::text[]
    when 'admin' then array['PAC', 'CHARLIE']::text[]
    when 'soc_lead' then array['PAC', 'CHARLIE']::text[]
    when 'l2' then array['PAC', 'CHARLIE']::text[]
    when 'l1' then array[]::text[]
    else null
  end;

  if p_operation = 'create' then
    insert into public.app_users (username, password_hash, role, team_access, created_by)
    values (p_username, p_password_hash, p_role, coalesce(mapped_team_access, array[]::text[]), p_actor_id)
    returning * into target;
  elsif p_operation = 'update' then
    update public.app_users set
      username = coalesce(p_username, username),
      password_hash = coalesce(p_password_hash, password_hash),
      role = coalesce(p_role, role),
      team_access = coalesce(mapped_team_access, team_access)
    where id = p_target_id returning * into target;
    if target.id is null then raise exception 'user not found' using errcode = 'P0002'; end if;
  elsif p_operation = 'delete' then
    if p_target_id = p_actor_id then raise exception 'cannot delete own account' using errcode = '22023'; end if;
    select * into target from public.app_users where id = p_target_id;
    if target.id is null then raise exception 'user not found' using errcode = 'P0002'; end if;
    delete from public.app_users where id = p_target_id;
  else
    raise exception 'invalid user mutation' using errcode = '22023';
  end if;

  insert into public.audit_log (actor_id, actor_username, action, target, detail)
  values (p_actor_id, actor_username, 'user.' || p_operation, coalesce(target.username, p_target_id::text), p_detail);
  return to_jsonb(target) - 'password_hash';
end;
$$;

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
  actor_team_access text[];
  changed text[] := array[]::text[];
  requested_count integer := coalesce(array_length(p_ips, 1), 0);
begin
  select role, username, team_access into actor_role, actor_username, actor_team_access
  from public.app_users where id = p_actor_id;
  if actor_role is null then raise exception 'current account not found' using errcode = '42501'; end if;
  if p_team not in ('PAC', 'CHARLIE') or p_operation not in ('insert', 'delete') then
    raise exception 'invalid team filter mutation' using errcode = '22023';
  end if;
  if not (p_team = any(actor_team_access)) then
    raise exception 'team access denied' using errcode = '42501';
  end if;

  if p_operation = 'insert' then
    with inserted as (
      insert into public.team_filter_ips (team, ip, payload, updated_by)
      select p_team, value::inet, jsonb_build_object('ioc', value), p_actor_id
      from unnest(p_ips) value
      on conflict (team, ip) do nothing
      returning host(ip) as ip
    ) select coalesce(array_agg(ip), array[]::text[]) into changed from inserted;
  else
    with deleted as (
      delete from public.team_filter_ips
      where team = p_team and ip = any(p_ips::inet[])
      returning host(ip) as ip
    ) select coalesce(array_agg(ip), array[]::text[]) into changed from deleted;
  end if;

  insert into public.team_filter_audit (
    request_id, actor_id, actor_username, team, operation,
    item_count, execution_time_ms, status, detail
  ) values (
    p_request_id, p_actor_id, actor_username, p_team, p_operation,
    cardinality(changed), greatest(p_execution_time_ms, 0), 'ok',
    jsonb_build_object('requested', requested_count, 'skipped', requested_count - cardinality(changed))
  );
  return jsonb_build_object('ips', to_jsonb(changed), 'changed_count', cardinality(changed), 'skipped_count', requested_count - cardinality(changed));
end;
$$;

create or replace function public.mutate_charlie_client_filter(
  p_client_id bigint,
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
  actor_team_access text[];
  client_code text;
  changed text[] := array[]::text[];
  requested_count integer := coalesce(array_length(p_ips, 1), 0);
begin
  select role, username, team_access into actor_role, actor_username, actor_team_access
  from public.app_users where id = p_actor_id;
  if actor_role is null then raise exception 'current account not found' using errcode = '42501'; end if;
  if not ('CHARLIE' = any(actor_team_access)) then
    raise exception 'Charlie client access denied' using errcode = '42501';
  end if;
  if p_operation not in ('insert', 'delete') then
    raise exception 'invalid Charlie client filter operation' using errcode = '22023';
  end if;
  select code into client_code from public.charlie_filter_clients
  where id = p_client_id and active = true;
  if client_code is null then raise exception 'Charlie client not found' using errcode = 'P0002'; end if;
  if client_code = 'GENERAL' then raise exception 'GENERAL uses legacy team filter path' using errcode = '22023'; end if;

  if p_operation = 'insert' then
    with inserted as (
      insert into public.charlie_client_filter_ips (client_id, ip, payload, updated_by)
      select p_client_id, value::inet, jsonb_build_object('ioc', value), p_actor_id
      from unnest(p_ips) value
      on conflict (client_id, ip) do nothing
      returning host(ip) as ip
    ) select coalesce(array_agg(ip), array[]::text[]) into changed from inserted;
  else
    with deleted as (
      delete from public.charlie_client_filter_ips
      where client_id = p_client_id and ip = any(p_ips::inet[])
      returning host(ip) as ip
    ) select coalesce(array_agg(ip), array[]::text[]) into changed from deleted;
  end if;

  insert into public.charlie_client_filter_audit (
    request_id, actor_id, actor_username, client_id, client_code, operation,
    item_count, execution_time_ms, status, detail
  ) values (
    p_request_id, p_actor_id, actor_username, p_client_id, client_code, p_operation,
    cardinality(changed), greatest(coalesce(p_execution_time_ms, 0), 0), 'ok',
    jsonb_build_object('requested', requested_count, 'skipped', requested_count - cardinality(changed))
  );
  return jsonb_build_object('ips', to_jsonb(changed), 'changed_count', cardinality(changed), 'skipped_count', requested_count - cardinality(changed));
end;
$$;

revoke all on function public.mutate_app_user_v2(uuid, text, uuid, text, text, text, jsonb, text[]) from public, anon, authenticated;
grant execute on function public.mutate_app_user_v2(uuid, text, uuid, text, text, text, jsonb, text[]) to service_role;

-- Existing production signatures stay callable only by server service role.
revoke all on function public.mutate_team_filter(text, text, text[], uuid, text, text, integer) from public, anon, authenticated;
grant execute on function public.mutate_team_filter(text, text, text[], uuid, text, text, integer) to service_role;
revoke all on function public.mutate_charlie_client_filter(bigint, text, text[], uuid, text, text, integer) from public, anon, authenticated;
grant execute on function public.mutate_charlie_client_filter(bigint, text, text[], uuid, text, text, integer) to service_role;

comment on column public.app_users.team_access is 'Authoritative PAC/CHARLIE memberships, independent from authority role.';

commit;
