# SOC Toolbox

Internal SOC analyst utilities — IP Formatter, JSON Merger, VirusTotal Lookup.

## Deploy ke Vercel

### 1. Clone / upload project
```
soc-toolbox/
├── api/
│   └── vt.js          ← serverless proxy (API key aman di sini)
├── public/
│   └── index.html     ← frontend
├── vercel.json
├── .env.example
└── README.md
```

### 2. Set environment variable
Di **Vercel Dashboard → Project → Settings → Environment Variables**:
```
VT_API_KEY = <your_virustotal_api_key>
```
Atau untuk local dev, buat file `.env.local`:
```
VT_API_KEY=your_key_here
```

### 3. Deploy
```bash
npm i -g vercel
vercel --prod
```

## Kenapa pakai serverless proxy?

- API key **tidak pernah expose ke browser** — aman dari inspect element / network tab
- Tidak kena CORS block karena request ke VT jalan dari server Vercel, bukan dari browser user
- Free tier Vercel cukup untuk penggunaan internal SOC

## Local dev
```bash
npm i -g vercel
vercel dev
# buka http://localhost:3000
```