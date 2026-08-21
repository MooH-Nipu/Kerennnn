-- Kerennnn audit and privileged-mutation hardening.
-- Apply after app_users.sql, audit_log.sql, and team_filter.sql.
begin;

create or replace function public.reject_audit_mutation()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  raise exception 'audit rows are immutable' using errcode = '42501';
end;
$$;

-- Preserve immutable actor UUID + username snapshots without coupling account deletion.
alter table public.team_filter_audit drop constraint if exists team_filter_audit_actor_id_fkey;

-- Denials can occur before a valid team context exists.
alter table public.team_filter_audit alter column team drop not null;

drop trigger if exists team_filter_audit_immutable on public.team_filter_audit;
create trigger team_filter_audit_immutable
before update or delete on public.team_filter_audit
for each row execute function public.reject_audit_mutation();

drop trigger if exists audit_log_immutable on public.audit_log;
create trigger audit_log_immutable
before update or delete on public.audit_log
for each row execute function public.reject_audit_mutation();

revoke update, delete on public.team_filter_audit from service_role;
revoke update, delete on public.audit_log from service_role;
grant select, insert on public.team_filter_audit to service_role;
grant select, insert on public.audit_log to service_role;

create or replace function public.record_team_filter_event(
  p_actor_id uuid,
  p_request_id text,
  p_team text,
  p_operation text,
  p_status text,
  p_item_count integer,
  p_execution_time_ms integer,
  p_detail jsonb default null
)
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  actor_role text;
  actor_username text;
begin
  select role, username into actor_role, actor_username
  from public.app_users where id = p_actor_id;
  if actor_role is null then raise exception 'current account not found' using errcode = '42501'; end if;
  if p_team is not null and p_team not in ('PAC', 'CHARLIE') then raise exception 'invalid team' using errcode = '22023'; end if;
  if p_operation not in ('list', 'insert', 'delete') or p_status not in ('ok', 'denied', 'error') then
    raise exception 'invalid audit event' using errcode = '22023';
  end if;
  insert into public.team_filter_audit (
    request_id, actor_id, actor_username, team, operation,
    item_count, execution_time_ms, status, detail
  ) values (
    p_request_id, p_actor_id, actor_username, p_team, p_operation,
    greatest(coalesce(p_item_count, 0), 0), greatest(coalesce(p_execution_time_ms, 0), 0), p_status, p_detail
  );
end;
$$;

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
begin
  select role, username into actor_role, actor_username
  from public.app_users where id = p_actor_id;
  if actor_role not in ('admin', 'l2') then raise exception 'admin access denied' using errcode = '42501'; end if;
  if p_role is not null and p_role not in ('admin', 'soc_lead', 'pac', 'charlie', 'l1', 'l2') then
    raise exception 'invalid role' using errcode = '22023';
  end if;

  if p_operation = 'create' then
    insert into public.app_users (username, password_hash, role, created_by)
    values (p_username, p_password_hash, p_role, p_actor_id)
    returning * into target;
  elsif p_operation = 'update' then
    update public.app_users set
      username = coalesce(p_username, username),
      password_hash = coalesce(p_password_hash, password_hash),
      role = coalesce(p_role, role)
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

  return jsonb_build_object(
    'id', target.id, 'username', target.username, 'role', target.role, 'created_at', target.created_at
  );
end;
$$;

revoke all on function public.reject_audit_mutation() from public, anon, authenticated;
revoke all on function public.record_team_filter_event(uuid, text, text, text, text, integer, integer, jsonb) from public, anon, authenticated;
revoke all on function public.mutate_app_user(uuid, text, uuid, text, text, text, jsonb) from public, anon, authenticated;
grant execute on function public.record_team_filter_event(uuid, text, text, text, text, integer, integer, jsonb) to service_role;
grant execute on function public.mutate_app_user(uuid, text, uuid, text, text, text, jsonb) to service_role;

commit;
