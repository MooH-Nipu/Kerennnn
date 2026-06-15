-- Run in Supabase SQL Editor (public schema).
-- Postgres function that aggregates api_usage data server-side so the
-- /api/admin/usage handler makes ONE round-trip instead of pulling raw
-- rows into memory. v3: accepts from/to timestamps instead of days.

drop function if exists public.get_api_usage_stats(integer);
drop function if exists public.get_api_usage_stats(integer, text);

create or replace function public.get_api_usage_stats(
  from_ts     timestamptz,
  to_ts       timestamptz,
  bucket_param text default '1d'
)
returns jsonb
language plpgsql stable
as $$
declare
  raw_total   bigint;
  by_outcome  jsonb;
  by_user     jsonb;
  by_day      jsonb;
  recent_rows jsonb;
begin
  -- Total rows in window (uncapped, includes ATT&CK / NVD).
  select count(*) into raw_total from public.api_usage
  where created_at >= from_ts and created_at < to_ts;

  -- By outcome (for the summary stat cards).
  select coalesce(jsonb_agg(
    jsonb_build_object('outcome', outcome, 'total', c)
    order by c desc
  ), '[]'::jsonb)
  into by_outcome
  from (
    select coalesce(outcome, 'ok') as outcome, count(*) as c
    from public.api_usage
    where created_at >= from_ts and created_at < to_ts
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
    where created_at >= from_ts and created_at < to_ts
      and service not in ('ATT&CK', 'NVD')
    group by username
    order by total desc
  ) sub;

  -- Per-service per-bucket (for the TI usage-over-time chart) — excludes ATT&CK / NVD.
  -- Bucket granularities: '30m' = 30-minute, '1d' = daily, '1w' = weekly (Monday start).
  -- Each returned row is { day: "2026-06-14T14:00", "VirusTotal": 42, … }.
  select coalesce(jsonb_agg(entry order by sort_key), '[]'::jsonb)
  into by_day
  from (
    select jsonb_build_object('day', label) || jsonb_object_agg(service, c) as entry,
           sort_key
    from (
      select
        case bucket_param
          when '30m' then to_char(
            date_trunc('hour', created_at) +
              (floor(extract(minute from created_at) / 30) * 30 || ' minutes')::interval,
            'YYYY-MM-DD HH24:MI'
          )
          when '1w'  then to_char(date_trunc('week', created_at)::date, 'YYYY-MM-DD')
          else            to_char(created_at::date, 'YYYY-MM-DD')
        end as label,
        case bucket_param
          when '30m' then date_trunc('hour', created_at) +
              (floor(extract(minute from created_at) / 30) * 30 || ' minutes')::interval
          when '1w'  then date_trunc('week', created_at)::date
          else            created_at::date
        end as sort_key,
        service,
        count(*) as c
      from public.api_usage
      where created_at >= from_ts and created_at < to_ts
        and service not in ('ATT&CK', 'NVD')
      group by sort_key, label, service
    ) agg
    group by label, sort_key
  ) outer_sub;

  -- Recent 10 rows.
  select coalesce(jsonb_agg(row_to_json(t) order by created_at desc), '[]'::jsonb)
  into recent_rows
  from (
    select username, service, ioc_type, outcome, api_key, created_at
    from public.api_usage
    where created_at >= from_ts and created_at < to_ts
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
