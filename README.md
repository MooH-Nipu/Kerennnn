# soc-toolbox (Charlie kerennnn)

React + Vite single-page app (entry `index.html` → `src/main.tsx`, base styles in `styles.css`) plus Vercel serverless routes under `api/`. VirusTotal and correlation features call same-origin `/api/*` from the browser.

## Deploy (Vercel)

Connect the repository, use the default Node runtime, and deploy. Static files at the repo root are served as-is; API handlers live in `api/` (see [Vercel serverless functions](https://vercel.com/docs/functions/serverless-functions)).

## Database (Supabase)

PAC Filter tab persists IPs to the database (Supabase). Apply SQL in order:

1. [supabase/app_users.sql](supabase/app_users.sql) — multi-user auth table
2. [supabase/merger_scanned_ips.sql](supabase/merger_scanned_ips.sql)
3. [supabase/merger_scanned_ips_timestamp_wib.sql](supabase/merger_scanned_ips_timestamp_wib.sql) (if you use the timestamp column)
4. [supabase/vt_ip_cache.sql](supabase/vt_ip_cache.sql) — VT IP scan cache
5. [supabase/login_attempts.sql](supabase/login_attempts.sql) — brute-force lockout for login
6. [supabase/audit_log.sql](supabase/audit_log.sql) — admin action audit trail
7. [supabase/scan_history.sql](supabase/scan_history.sql) — per-user IoC scan history

Set the environment variables below, then use **Refresh dari DB** in the UI.

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
| `GREYNOISE_API_KEY` | `api/correlate.js` | GreyNoise — noise/scanner classification (IP only). Free community tier available |
| `URLSCAN_API_KEY` | `api/correlate.js` | URLScan.io — live browser scan + screenshot (domain only). Adds ~10–15s latency for domain IOCs |
| `SHODAN_API_KEY` | `api/correlate.js` | Shodan — open ports + known CVEs (IP only, context source). Free tier: 100 queries/month |
| `PULSEDIVE_API_KEY` | `api/correlate.js` | Pulsedive — risk-scored IOC enrichment (all types). Free tier available |
| `CRIMINAL_IP_API_KEY` | `api/correlate.js` | Criminal IP — APAC-focused threat intelligence (IP + domain). Free tier available |
| `IPINFO_TOKEN` | `api/correlate.js` | Optional. GeoIP enrichment via ipinfo.io. If unset, falls back to keyless `ipwho.is`. RDAP uses keyless `rdap.org`. MalwareBazaar and ThreatFox are also keyless |
| `TRUST_VT` | `api/correlate.js` | Optional weight multiplier for VirusTotal (base 0.30) |
| `TRUST_ABUSEIPDB` | `api/correlate.js` | Optional weight multiplier for AbuseIPDB (base 0.20) |
| `TRUST_ABUSECH` | `api/correlate.js` | Optional weight multiplier for Abuse.ch / URLhaus (base 0.20) |
| `TRUST_OTX` | `api/correlate.js` | Optional weight multiplier for AlienVault OTX (base 0.15) |
| `TRUST_GREYNOISE` | `api/correlate.js` | Optional weight multiplier for GreyNoise (base 0.25) |
| `TRUST_URLSCAN` | `api/correlate.js` | Optional weight multiplier for URLScan.io (base 0.20) |
| `TRUST_MALWAREBAZAAR` | `api/correlate.js` | Optional weight multiplier for MalwareBazaar (base 0.25) |
| `TRUST_THREATFOX` | `api/correlate.js` | Optional weight multiplier for ThreatFox (base 0.15) |
| `TRUST_PULSEDIVE` | `api/correlate.js` | Optional weight multiplier for Pulsedive (base 0.10) |
| `TRUST_CRIMINAL_IP` | `api/correlate.js` | Optional weight multiplier for Criminal IP (base 0.12) |

**Correlation source weights** (base values, higher = more trusted):
VirusTotal 0.30 · GreyNoise 0.25 · MalwareBazaar 0.25 · AbuseIPDB 0.20 · Abuse.ch 0.20 · URLScan.io 0.20 · OTX 0.15 · ThreatFox 0.15 · Criminal IP 0.12 · Pulsedive 0.10.
Shodan and Enrichment (RDAP/GeoIP) are **context-only** — no verdict/weight, contribute only via risk-factor bonuses.
Sources with no API key configured are silently excluded from results (no "SKIPPED" rows shown).

The front end stores the VirusTotal key in **localStorage** for browser calls; server routes use env keys for `/api/vt` and correlation.

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
- **Login brute-force** is rate-limited per (username, IP) via the
  `login_attempts` table; admin user changes are recorded in `audit_log`.
- **Security headers** (CSP, HSTS, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`) are set in `server.js`
  for self-hosting and mirrored in `vercel.json` for the Vercel deployment.
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

There is no bundled dev server in this repo. Options:

- Open `index.html` directly for UI-only checks (API calls will fail unless you point a dev proxy at a deployed backend or run a compatible local server).
- Or use [Vercel CLI](https://vercel.com/docs/cli) (`vercel dev`) from the project root with env vars in `.env.local`.
