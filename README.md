# soc-toolbox (Charlie kerennnn)

Static UI (`index.html`, `styles.css`, `app.js`) plus Vercel serverless routes under `api/`. VirusTotal and correlation features call `/api/*` from the browser.

## Deploy (Vercel)

Connect the repository, use the default Node runtime, and deploy. Static files at the repo root are served as-is; API handlers live in `api/` (see [Vercel serverless functions](https://vercel.com/docs/functions/serverless-functions)).

## Database (Supabase)

PAC Filter tab persists IPs to the database (Supabase). Apply SQL in order:

1. [supabase/merger_scanned_ips.sql](supabase/merger_scanned_ips.sql)
2. [supabase/merger_scanned_ips_timestamp_wib.sql](supabase/merger_scanned_ips_timestamp_wib.sql) (if you use the timestamp column)

Set the environment variables below, then use **Refresh dari DB** in the UI.

## Environment variables

| Variable | Used by | Purpose |
| --- | --- | --- |
| `SUPABASE_URL` | `api/scan-merger.js` | Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | `api/scan-merger.js` | Service role key (server only; never expose to the client) |
| `MERGER_API_PASSWORD` | `api/scan-merger.js` | Optional. If set, requests must send header `X-Merger-Password` with this value |
| `VT_API_KEY` | `api/vt.js`, `api/correlate.js`, `api/health.js` | VirusTotal API key |
| `VT_API_KEY_2` … `VT_API_KEY_10` | same | Optional extra VT keys for rotation |
| `ABUSEIPDB_API_KEY` | `api/correlate.js` | AbuseIPDB |
| `ABUSECH_API_KEY` or `URLHAUS_API_KEY` | `api/correlate.js` | Abuse.ch / URLhaus |
| `OTX_API_KEY` | `api/correlate.js` | AlienVault OTX |
| `GREYNOISE_API_KEY` | `api/correlate.js` | GreyNoise |
| `TRUST_VT`, `TRUST_ABUSEIPDB`, `TRUST_ABUSECH`, `TRUST_OTX` | `api/correlate.js` | Optional numeric weights (defaults apply if unset) |

The front end stores the VirusTotal key in **localStorage** for browser calls; server routes use env keys for `/api/vt` and correlation.

## Scripts

- `npm test` — run Node tests (e.g. `api/_ioc.test.js`)
- `npm run lint` — ESLint on `api/`
- `npm run format` — Prettier write for `api/**/*.js`

## Local development

There is no bundled dev server in this repo. Options:

- Open `index.html` directly for UI-only checks (API calls will fail unless you point a dev proxy at a deployed backend or run a compatible local server).
- Or use [Vercel CLI](https://vercel.com/docs/cli) (`vercel dev`) from the project root with env vars in `.env.local`.
