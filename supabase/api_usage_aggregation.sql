-- Run in Supabase SQL Editor (public schema).
-- Postgres function that aggregates api_usage data server-side so the
-- /api/admin/usage handler makes ONE round-trip instead of pulling raw
-- rows into memory. Replaces the old paginated JS aggregation.

create or replace function public.get_api_usage_stats(days_param integer)
returns jsonb
language plpgsql stable
as $$
declare
  cutoff_ts timestamptz;
  raw_total bigint;
  by_outcome jsonb;
  by_user    jsonb;
  by_day     jsonb;
  recent_rows jsonb;
begin
  cutoff_ts := now() - (days_param || ' days')::interval;

  -- Total rows in window (uncapped, includes ATT&CK / NVD).
  select count(*) into raw_total from public.api_usage
  where created_at >= cutoff_ts;

  -- By outcome (for the summary stat cards).
  select coalesce(jsonb_agg(
    jsonb_build_object('outcome', outcome, 'total', c)
    order by c desc
  ), '[]'::jsonb)
  into by_outcome
  from (
    select coalesce(outcome, 'ok') as outcome, count(*) as c
    from public.api_usage
    where created_at >= cutoff_ts
    group by outcome
  ) sub;

  -- By user — excludes ATT&CK / NVD (separate analyst tools, not IoC scan).
  select coalesce(jsonb_agg(
    jsonb_build_object(
      'username', username,
      'total', total,
      'ok', ok,
      'rate_limited', rate_limited,
      'error', error
    ) order by total desc
  ), '[]'::jsonb)
  into by_user
  from (
    select
      coalesce(username, '(unknown)') as username,
      count(*) as total,
      count(*) filter (where outcome = 'ok') as ok,
      count(*) filter (where outcome = 'rate_limited') as rate_limited,
      count(*) filter (where outcome = 'error') as error
    from public.api_usage
    where created_at >= cutoff_ts
      and service not in ('ATT&CK', 'NVD')
    group by username
    order by total desc
  ) sub;

  -- Per-service per-day (for the TI usage-over-time chart) — excludes ATT&CK / NVD.
  -- Each returned row is { day: "2026-06-01", "VirusTotal": 42, "AbuseIPDB": 15, … }.
  select coalesce(jsonb_agg(entry order by day), '[]'::jsonb)
  into by_day
  from (
    select jsonb_build_object('day', d::text) || jsonb_object_agg(service, c) as entry,
           d as day
    from (
      select created_at::date as d, service, count(*) as c
      from public.api_usage
      where created_at >= cutoff_ts
        and service not in ('ATT&CK', 'NVD')
      group by d, service
    ) agg
    group by d
  ) outer_sub;

  -- Recent 10 rows.
  select coalesce(jsonb_agg(row_to_json(t) order by created_at desc), '[]'::jsonb)
  into recent_rows
  from (
    select username, service, ioc_type, outcome, api_key, created_at
    from public.api_usage
    where created_at >= cutoff_ts
    order by created_at desc
    limit 10
  ) t;

  return jsonb_build_object(
    'total', raw_total,
    'byOutcome', by_outcome,
    'byUser', by_user,
    'byDay', by_day,
    'recent', recent_rows
  );
end;
$$;
