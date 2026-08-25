-- Bounded storage retention for the Supabase free plan.
-- Keeps audit tables untouched.

create extension if not exists pg_cron with schema pg_catalog;

create or replace function public.prune_storage_retention()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  scan_deleted bigint;
  usage_deleted bigint;
  login_deleted bigint;
begin
  with ranked as (
    select id,
           row_number() over (partition by user_id order by created_at desc, id desc) as rn
    from public.scan_history
  ), deleted as (
    delete from public.scan_history
    where id in (select id from ranked where rn > 20)
    returning 1
  )
  select count(*) into scan_deleted from deleted;

  with deleted as (
    delete from public.api_usage
    where created_at < now() - interval '90 days'
    returning 1
  )
  select count(*) into usage_deleted from deleted;

  with deleted as (
    delete from public.login_attempts
    where attempted_at < now() - interval '7 days'
    returning 1
  )
  select count(*) into login_deleted from deleted;

  return jsonb_build_object(
    'scan_history', scan_deleted,
    'api_usage', usage_deleted,
    'login_attempts', login_deleted
  );
end;
$$;

revoke all on function public.prune_storage_retention() from public, anon, authenticated;
grant execute on function public.prune_storage_retention() to service_role;

comment on function public.prune_storage_retention() is
  'Keeps 20 newest scan_history rows per user, 90 days of api_usage, and 7 days of login_attempts. Audit tables are never pruned.';

do $$
declare
  existing_job record;
begin
  for existing_job in
    select jobid from cron.job
    where jobname = 'kerennnn-storage-retention'
  loop
    perform cron.unschedule(existing_job.jobid);
  end loop;

  -- Supabase databases and pg_cron run in UTC: 03:00 UTC = 10:00 WIB.
  perform cron.schedule(
    'kerennnn-storage-retention',
    '0 3 * * *',
    'select public.prune_storage_retention();'
  );
end;
$$;
