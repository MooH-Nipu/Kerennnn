-- Roll back only parallel Charlie multi-client storage.
-- Application must be rolled back first so it no longer calls these objects.
-- This intentionally leaves team_filter_ips, team_filter_audit, and
-- mutate_team_filter untouched for shared-DB production compatibility.

begin;

drop function if exists public.create_charlie_filter_client(text, text, uuid);
drop function if exists public.mutate_charlie_client_filter(bigint, text, text[], uuid, text, text, integer);
drop table if exists public.charlie_client_filter_audit;
drop table if exists public.charlie_client_filter_ips;
drop table if exists public.charlie_filter_clients;

notify pgrst, 'reload schema';
commit;
