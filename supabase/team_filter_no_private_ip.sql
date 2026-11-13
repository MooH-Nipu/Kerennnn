-- Private/reserved IPv4 must never enter the filter DB.
-- App-side gates: api/team-filter.js, api/scan-merger.js. This is the backstop.
--
-- NOT VALID on purpose: legacy rows (if any) stay untouched and purgeable, but
-- every new insert/update must satisfy the check. Run
--   ALTER TABLE public.team_filter_ips VALIDATE CONSTRAINT team_filter_ips_public_ip;
-- once the legacy audit is clean.
begin;

alter table public.team_filter_ips
  add constraint team_filter_ips_public_ip check (
    not (
      ip <<= '0.0.0.0/8'::inet
      or ip <<= '10.0.0.0/8'::inet
      or ip <<= '100.64.0.0/10'::inet
      or ip <<= '127.0.0.0/8'::inet
      or ip <<= '169.254.0.0/16'::inet
      or ip <<= '172.16.0.0/12'::inet
      or ip <<= '192.0.0.0/24'::inet
      or ip <<= '192.168.0.0/16'::inet
      or ip <<= '224.0.0.0/4'::inet
      or ip <<= '240.0.0.0/4'::inet
    )
  ) not valid;

commit;
