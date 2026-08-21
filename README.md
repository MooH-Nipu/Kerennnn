# soc-toolbox (Charlie kerennnn)

React + Vite single-page app (entry `index.html` → `src/main.tsx`, base styles in `styles.css`) plus Vercel serverless routes under `api/`. VirusTotal and correlation features call same-origin `/api/*` from the browser.

## Deploy

Production uses Docker on port `3000`. `dist/` is generated inside the multi-stage image and intentionally not tracked. Vercel is retired.

## Database (Supabase)

Apply SQL in this order:

1. [supabase/app_users.sql](supabase/app_users.sql)
2. [supabase/merger_scanned_ips.sql](supabase/merger_scanned_ips.sql)
3. [supabase/merger_scanned_ips_timestamp_wib.sql](supabase/merger_scanned_ips_timestamp_wib.sql)
4. [supabase/vt_ip_cache.sql](supabase/vt_ip_cache.sql)
5. [supabase/login_attempts.sql](supabase/login_attempts.sql)
6. [supabase/audit_log.sql](supabase/audit_log.sql)
7. [supabase/team_filter.sql](supabase/team_filter.sql)
8. [supabase/security_hardening.sql](supabase/security_hardening.sql)
9. [supabase/scan_history.sql](supabase/scan_history.sql)

### Security migration release procedure

**Backup before migration:** export `app_users`, `audit_log`, `merger_scanned_ips`, `team_filter_ips`, and `team_filter_audit` from Supabase.

Verify after applying:

```sql
select trigger_name from information_schema.triggers
where trigger_name in ('team_filter_audit_immutable', 'audit_log_immutable');

select routine_name from information_schema.routines
where routine_schema = 'public'
  and routine_name in ('mutate_team_filter', 'record_team_filter_event', 'mutate_app_user');

select team, count(*) from public.team_filter_ips group by team order by team;
```

Before required migrations exist, authorized Team Filter requests intentionally return `503 ERR_SCHEMA_NOT_READY`.

**Rollback:** roll application back first. Keep data and audit tables intact, then remove only hardening wrappers:

```sql
begin;
drop trigger if exists team_filter_audit_immutable on public.team_filter_audit;
drop trigger if exists audit_log_immutable on public.audit_log;
drop function if exists public.record_team_filter_event(uuid, text, text, text, text, integer, integer, jsonb);
drop function if exists public.mutate_app_user(uuid, text, uuid, text, text, text, jsonb);
drop function if exists public.reject_audit_mutation();
commit;
```

Production uses Docker named volume `kerennnn-data` for writable VT quota state. Copy existing `data/vt-key-state.json` into that volume before first hardened recreate.

## Environment variables

| Variable | Used by | Purpose |
| --- | --- | --- |
| `SUPABASE_URL` | all DB handlers | Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | all DB handlers | Service role key (server only; **bypasses RLS** — never expose to the client) |
| `APP_AUTH_SECRET` | `api/_auth.js`, `api/auth/login.js` | **Required for auth.** HMAC secret for signing session cookies. All `/api/*` data endpoints reject requests without a valid session |
| `COOKIE_SECURE` | `api/_auth.js` | Optional. Force the `Secure` cookie flag (defaults to on in production) |
| `LOGIN_MAX_ATTEMPTS` | `api/_ratelimit.js` | Optional. Failed logins per (username, IP) before lockout (default 10) |
| `LOGIN_WINDOW_MINUTES` | `api/_ratelimit.js` | Optional. Lockout window in minutes (default 15) |
| `MERGER_API_PASSWORD` | `api/scan-merger.js` | Optional. If set, requests must also send header `X-Merger-Password` with this value |
| `VT_API_KEY` | `api/vt.js`, `api/correlate.js`, `api/health.js` | VirusTotal API key |
| `VT_API_KEY_2` … `VT_API_KEY_10` | same | Optional extra VT keys for rotation |
| `ABUSEIPDB_API_KEY` | `api/correlate.js` | AbuseIPDB (IP only) |
| `ABUSECH_API_KEY` or `URLHAUS_API_KEY` | `api/correlate.js` | Abuse.ch / URLhaus (IP + domain) |
| `OTX_API_KEY` | `api/correlate.js` | AlienVault OTX (all types) |
| `URLSCAN_API_KEY` | `api/correlate.js` | URLScan.io — live browser scan + screenshot (domain only). Adds ~10–15s latency for domain IOCs |
| `IPINFO_TOKEN` | `api/correlate.js` | Optional. GeoIP enrichment via ipinfo.io. If unset, falls back to keyless `ipwho.is`. RDAP uses keyless `rdap.org` |
| `TRUST_VT` | `api/correlate.js` | Optional weight multiplier for VirusTotal (base 0.30) |
| `TRUST_ABUSEIPDB` | `api/correlate.js` | Optional weight multiplier for AbuseIPDB (base 0.20) |
| `TRUST_ABUSECH` | `api/correlate.js` | Optional weight multiplier for Abuse.ch / URLhaus (base 0.20) |
| `TRUST_OTX` | `api/correlate.js` | Optional weight multiplier for AlienVault OTX (base 0.15) |
| `TRUST_URLSCAN` | `api/correlate.js` | Optional weight multiplier for URLScan.io (base 0.20) |

**Correlation source weights** (base values, higher = more trusted):
VirusTotal 0.30 · AbuseIPDB 0.20 · Abuse.ch 0.20 · URLScan.io 0.20 · OTX 0.15.
Enrichment (RDAP/GeoIP) is **context-only** — no verdict/weight, contributes only via risk-factor bonuses.
Sources with no API key configured are silently excluded from results (no "SKIPPED" rows shown).

Threat-intelligence credentials stay server-side. Frontend calls same-origin `/api/*` routes only.

## Security / trust boundary

- **The API is the only trust boundary.** Every handler uses
  `SUPABASE_SERVICE_ROLE_KEY`, which **bypasses Row Level Security**. There is no
  RLS enforcement at the database layer — access control is enforced entirely in
  the `api/` handlers via `requireAuth` / `requireRole` (see `api/_auth.js`).
- **Never call Supabase from the browser** and never ship the service-role key to
  the client. The frontend talks only to same-origin `/api/*` routes.
- **Authentication is mandatory.** `/api/vt`, `/api/correlate`, `/api/scan-merger`,
  `/api/ir-cases*`, and `/api/ip-cache/*` (writes) all require a valid session
  cookie. `/api/admin/users` and `/api/ip-cache/cleanup` additionally require the
  `admin` role.
- **Login brute-force** uses persistent username+IP history plus a fail-safe local per-IP budget when database logging is unavailable.
- **Audit trails are immutable.** Team Filter and admin-user mutations use database RPCs so state changes and success audits commit atomically; denied/failed Team Filter actions are recorded separately without payloads.
- **Security headers** (CSP, HSTS, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`) are set in `server.js`.
- **Error responses are sanitized** — raw Supabase/Postgres error messages are
  logged server-side and never returned to the client (`api/_errors.js`).

## Scripts

- `npm test` — run all Node tests under `api/` (`node --test api/`)
- `npm run lint` — ESLint on `api/` and `src/`
- `npm run typecheck` — `tsc --noEmit`
- `npm run format` — Prettier write for `api/**/*.js` and `src/**/*.{ts,tsx}`

CI runs lint → typecheck → tests → build on every push/PR
(see `.github/workflows/ci.yml`).

## Local development

Use `npm run dev` for the Vite frontend. API-backed workflows require the Docker app or [Vercel CLI](https://vercel.com/docs/cli) (`vercel dev`) with env vars in `.env.local`.
