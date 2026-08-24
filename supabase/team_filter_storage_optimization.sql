-- Consolidate PAC filter storage after verified JSONL exports.
-- team_filter_ips remains the canonical table; /api/scan-merger reads it directly.
begin;

-- Fail closed if legacy PAC storage differs from canonical storage.
do $$
declare
  membership_differences bigint;
  payload_differences bigint;
begin
  if to_regclass('public.merger_scanned_ips') is not null then
    execute $q$
      select count(*)
      from public.merger_scanned_ips m
      full join (
        select ip from public.team_filter_ips where team = 'PAC'
      ) t on t.ip = m.ip::inet
      where m.ip is null or t.ip is null
    $q$ into membership_differences;

    execute $q$
      select count(*)
      from public.merger_scanned_ips m
      join public.team_filter_ips t
        on t.team = 'PAC' and t.ip = m.ip::inet
      where m.payload is distinct from t.payload
    $q$ into payload_differences;

    if membership_differences <> 0 or payload_differences <> 0 then
      raise exception 'legacy PAC storage differs from team_filter_ips: membership %, payload %',
        membership_differences, payload_differences;
    end if;
  end if;
end;
$$;

-- Keep privileged mutation transactional, but stop duplicating PAC writes.
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
  select role, username into actor_role, actor_username
  from public.app_users where id = p_actor_id;
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

  return jsonb_build_object(
    'ips', to_jsonb(changed),
    'changed_count', cardinality(changed),
    'skipped_count', requested_count - cardinality(changed)
  );
end;
$$;

revoke all on function public.mutate_team_filter(text, text, text[], uuid, text, text, integer)
  from public, anon, authenticated;
grant execute on function public.mutate_team_filter(text, text, text[], uuid, text, text, integer)
  to service_role;

-- Remove compatibility machinery and archived redundant copies.
do $$
begin
  if to_regclass('public.merger_scanned_ips') is not null then
    execute 'drop trigger if exists merger_scanned_ips_team_bridge on public.merger_scanned_ips';
  end if;
end;
$$;
drop function if exists public.sync_legacy_pac_filter();
drop table if exists public.merger_scanned_ips_backup_juli;
drop table if exists public.merger_scanned_ips_backup_aug;
drop table if exists public.merger_scanned_ips;

-- Confirmed unused or duplicate indexes. Constraints and active indexes remain.
drop index if exists public.ip_scan_events_user_created_idx;
drop index if exists public.team_filter_ips_team_updated_idx;
drop index if exists public.vt_ip_cache_id_idx;
drop index if exists public.vt_ioc_cache_id_idx;

commit;
