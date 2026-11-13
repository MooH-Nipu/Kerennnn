# Kerennnn scan API (v1)

Base URL: `http://<host>:3000`. Every request needs a key created in
**Settings → API**. A user may hold several keys — one per integration, e.g.
`n8n prod`, `laptop cli`, `siem probe` — and each key carries its own ACL. The
secret is shown once at creation and cannot be recovered; keys are minted only
in the UI, never over the API.

```
Authorization: Bearer krn_<8 hex>_<32 chars>
```

`X-API-Key: <key>` is accepted as an alternative for clients that prefer it.

## Endpoints

| Method | Path | Scope | Purpose |
|---|---|---|---|
| POST | `/api/v1/scan` | `ioc:scan` | Scan 1–10 IOCs, return every verdict |
| GET | `/api/v1/verdict?ioc=` | `ioc:read` | Cached verdict, no upstream calls |
| GET | `/api/v1/me` | any | Key identity, scopes, allowed types |

Errors are `{ "ok": false, "error": { "code": "...", "message": "..." } }` with
HTTP 400/401/403/404/405/429/503.

## Scan

```bash
curl -s -X POST http://localhost:3000/api/v1/scan \
  -H "Authorization: Bearer $KRN" \
  -H 'Content-Type: application/json' \
  -d '{"iocs":["8.8.8.8","example.com"]}'
```

```json
{
  "ok": true,
  "key": { "prefix": "krn_1a2b3c4d", "scopes": ["ioc:scan", "ioc:read"], "allowedTypes": ["ip", "domain", "hash"] },
  "count": 1,
  "results": [{
    "ioc": "8.8.8.8",
    "type": "ip",
    "verdict": "HIGH RISK",
    "confidence": 78,
    "cached": true,
    "vt": { "verdict": "MALICIOUS", "malicious": 9, "suspicious": 2, "undetected": 60, "total": 71, "reputation": -12, "country": "NL", "asn": 15169, "asOwner": "GOOGLE" },
    "sources": [
      { "source": "VirusTotal", "verdict": "malicious", "score": 78, "weight": 1, "error": null },
      { "source": "AbuseIPDB", "verdict": "suspicious", "score": 55, "weight": 0.8, "error": null }
    ],
    "riskFactors": []
  }],
  "errors": []
}
```

`verdict` is the operational label derived from the blended confidence
(`HIGH RISK` ≥ 70, `MEDIUM RISK` ≥ 40, `LOW RISK` ≥ 15, else `LIKELY CLEAN`).
`vt.verdict` is the VirusTotal engine verdict. `sources[]` carries every
correlation source that actually ran, with its own verdict and score — that is
the "all verdicts" view.

Limits: 10 IOCs per request (hard cap 25 via `API_MAX_IOCS_PER_REQUEST`), plus the
existing per-user scan budget (100/min) and the per-IP request limiter (100/min).
Domain scans can take up to 45 s each because URLScan submits and polls.

## Cached verdict

```bash
curl -s "http://localhost:3000/api/v1/verdict?ioc=8.8.8.8" -H "Authorization: Bearer $KRN"
```

Returns `404 NOT_CACHED` when the IOC has never been scanned. No quota is spent.

## Keys and ACL

Each key has a label, `scopes` (`ioc:scan`, `ioc:read`) and `allowed_types`
(`ip`, `domain`, `hash`). A disallowed type comes back in `errors[]` as
`TYPE_NOT_ALLOWED`; a missing scope is `403 SCOPE_NOT_ALLOWED`. Up to 10 live keys
per user (`API_MAX_KEYS_PER_USER`, hard cap 25) — revoke one in Settings → API to
free a slot. Disabling a key keeps it listed but rejects its requests with
`401 INVALID_API_KEY`.
