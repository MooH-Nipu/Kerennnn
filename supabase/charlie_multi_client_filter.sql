-- Additive Charlie multi-client filter storage.
-- Safe with dev/prod sharing one Supabase project: this migration does not alter
-- team_filter_ips, team_filter_audit, mutate_team_filter, or any existing route.

begin;

create table if not exists public.charlie_filter_clients (
  id bigint generated always as identity primary key,
  code text not null unique check (code ~ '^[A-Z0-9_-]{2,32}$'),
  label text not null check (char_length(label) between 1 and 64),
  active boolean not null default true,
  sort_order integer not null default 100 check (sort_order >= 0),
  created_by uuid references public.app_users(id) on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists public.charlie_client_filter_ips (
  client_id bigint not null references public.charlie_filter_clients(id) on delete restrict,
  ip inet not null check (family(ip) = 4),
  payload jsonb not null default '{}'::jsonb,
  updated_by uuid references public.app_users(id) on delete set null,
  updated_at timestamptz not null default now(),
  primary key (client_id, ip)
);

create table if not exists public.charlie_client_filter_audit (
  id bigint generated always as identity primary key,
  request_id text not null unique,
  actor_id uuid,
  actor_username text not null,
  client_id bigint,
  client_code text not null,
  operation text not null check (operation in ('insert', 'delete')),
  item_count integer not null default 0 check (item_count >= 0),
  execution_time_ms integer not null check (execution_time_ms >= 0),
  status text not null check (status in ('ok', 'error')),
  detail jsonb,
  created_at timestamptz not null default now()
);

-- Audit stores immutable actor/client snapshots. Foreign keys with cascading
-- actions would attempt forbidden updates when an account/client is removed.
alter table public.charlie_client_filter_audit
  drop constraint if exists charlie_client_filter_audit_actor_id_fkey,
  drop constraint if exists charlie_client_filter_audit_client_id_fkey;

create index if not exists charlie_client_filter_audit_client_created_idx
  on public.charlie_client_filter_audit (client_id, created_at desc);
-- Primary key (client_id, ip) already covers client-scoped list/delete queries.

insert into public.charlie_filter_clients (code, label, sort_order)
values ('GENERAL', 'General / legacy list', 0)
on conflict (code) do update set label = excluded.label, active = true, sort_order = excluded.sort_order;

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
  client_code text;
  changed text[] := array[]::text[];
  requested_count integer := coalesce(array_length(p_ips, 1), 0);
begin
  select role, username into actor_role, actor_username
  from public.app_users where id = p_actor_id;
  if actor_role is null then raise exception 'current account not found' using errcode = '42501'; end if;
  if actor_role not in ('admin', 'soc_lead', 'l2', 'charlie') then
    raise exception 'Charlie client access denied' using errcode = '42501';
  end if;
  if p_operation not in ('insert', 'delete') then
    raise exception 'invalid Charlie client filter operation' using errcode = '22023';
  end if;
  select code into client_code from public.charlie_filter_clients
  where id = p_client_id and active = true;
  if client_code is null then raise exception 'Charlie client not found' using errcode = 'P0002'; end if;
  if client_code = 'GENERAL' then
    raise exception 'GENERAL uses legacy team filter path' using errcode = '22023';
  end if;

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

  return jsonb_build_object(
    'ips', to_jsonb(changed),
    'changed_count', cardinality(changed),
    'skipped_count', requested_count - cardinality(changed)
  );
end;
$$;

create or replace function public.create_charlie_filter_client(
  p_code text,
  p_label text,
  p_actor_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  actor_role text;
  actor_username text;
  created public.charlie_filter_clients%rowtype;
begin
  select role, username into actor_role, actor_username
  from public.app_users where id = p_actor_id;
  if actor_role is null or actor_role not in ('admin', 'soc_lead', 'l2') then
    raise exception 'Charlie client management denied' using errcode = '42501';
  end if;
  if p_code is null or p_code !~ '^[A-Z0-9_-]{2,32}$' then
    raise exception 'invalid Charlie client code' using errcode = '22023';
  end if;
  if p_code = 'GENERAL' then raise exception 'GENERAL is reserved' using errcode = '22023'; end if;
  if p_label is null or char_length(trim(p_label)) not between 1 and 64 then
    raise exception 'invalid Charlie client label' using errcode = '22023';
  end if;

  insert into public.charlie_filter_clients (code, label, created_by)
  values (p_code, trim(p_label), p_actor_id)
  returning * into created;

  insert into public.audit_log (actor_id, actor_username, action, target, detail)
  values (p_actor_id, actor_username, 'charlie_client.create', p_code,
          jsonb_build_object('label', created.label));

  return jsonb_build_object('id', created.id, 'code', created.code, 'label', created.label);
end;
$$;

create or replace function public.delete_charlie_filter_client(
  p_code text,
  p_confirmation text,
  p_actor_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  actor_role text;
  actor_username text;
  target public.charlie_filter_clients%rowtype;
  deleted_ip_count integer;
begin
  select role, username into actor_role, actor_username
  from public.app_users where id = p_actor_id;
  if actor_role is null or actor_role not in ('admin', 'soc_lead', 'l2') then
    raise exception 'Charlie client management denied' using errcode = '42501';
  end if;
  if p_code is null or p_code !~ '^[A-Z0-9_-]{2,32}$' then
    raise exception 'invalid Charlie client code' using errcode = '22023';
  end if;
  if p_code = 'GENERAL' then raise exception 'GENERAL is reserved' using errcode = '22023'; end if;
  if p_confirmation is distinct from p_code then
    raise exception 'client code confirmation does not match' using errcode = '22023';
  end if;

  select * into target from public.charlie_filter_clients
  where code = p_code and active = true
  for update;
  if target.id is null then raise exception 'Charlie client not found' using errcode = 'P0002'; end if;

  delete from public.charlie_client_filter_ips where client_id = target.id;
  get diagnostics deleted_ip_count = row_count;
  delete from public.charlie_filter_clients where id = target.id;

  insert into public.audit_log (actor_id, actor_username, action, target, detail)
  values (p_actor_id, actor_username, 'charlie_client.delete', p_code,
          jsonb_build_object('label', target.label, 'deleted_ip_count', deleted_ip_count));

  return jsonb_build_object('code', target.code, 'label', target.label, 'deleted_ip_count', deleted_ip_count);
end;
$$;

-- Dedicated audit is append-only, matching existing audit posture.
drop trigger if exists charlie_client_filter_audit_immutable on public.charlie_client_filter_audit;
create trigger charlie_client_filter_audit_immutable
before update or delete on public.charlie_client_filter_audit
for each row execute function public.reject_audit_mutation();

revoke all on function public.mutate_charlie_client_filter(bigint, text, text[], uuid, text, text, integer)
  from public, anon, authenticated;
grant execute on function public.mutate_charlie_client_filter(bigint, text, text[], uuid, text, text, integer)
  to service_role;
revoke all on function public.create_charlie_filter_client(text, text, uuid)
  from public, anon, authenticated;
grant execute on function public.create_charlie_filter_client(text, text, uuid)
  to service_role;
revoke all on function public.delete_charlie_filter_client(text, text, uuid)
  from public, anon, authenticated;
grant execute on function public.delete_charlie_filter_client(text, text, uuid)
  to service_role;

alter table public.charlie_filter_clients enable row level security;
alter table public.charlie_client_filter_ips enable row level security;
alter table public.charlie_client_filter_audit enable row level security;
revoke all on public.charlie_filter_clients from anon, authenticated;
revoke all on public.charlie_client_filter_ips from anon, authenticated;
revoke all on public.charlie_client_filter_audit from anon, authenticated;
revoke all on sequence public.charlie_filter_clients_id_seq from anon, authenticated;
revoke all on sequence public.charlie_client_filter_audit_id_seq from anon, authenticated;

comment on table public.charlie_filter_clients is 'Parallel Charlie-only client registry; additive to legacy Team Filter storage.';
comment on table public.charlie_client_filter_ips is 'Client-separated Charlie IPv4 lists; GENERAL deliberately remains on legacy team_filter_ips.';

-- Ask PostgREST to discover new tables/functions immediately after commit.
notify pgrst, 'reload schema';

commit;
