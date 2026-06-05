// App changelog shown to users as an "Update changes" toast (UpdateToast.tsx).
//
// ⚠️ CONVENTION: whenever you ship a user-facing change, PREPEND a new entry
// here with a fresh `version` (bump the date/build). The toast pops once per
// user per version — bumping `version` is what makes everyone see the notice.
// Keep `changes` short, user-facing, and in Indonesian (the app's UI language).

export interface UpdateEntry {
  version: string; // unique id; bump to re-trigger the toast for everyone
  title: string;
  changes: string[];
}

export const UPDATES: UpdateEntry[] = [
  {
    version: '2026.06.06-1',
    title: 'Apa yang baru',
    changes: [
      '🧭 Urutkan tab sesukamu — cukup seret tab di navigasi ke posisi yang kamu mau. Tersimpan otomatis & tersinkron di akunmu.',
      '🧹 Tab baru: JSON Beautifier — rapikan atau minify JSON, plus dukungan log NDJSON.',
      '🔍 "Analisa Mendalam" kini tersedia untuk Domain & Hash, bukan cuma IP.',
    ],
  },
];

// Newest entry drives the toast.
export const LATEST_UPDATE: UpdateEntry = UPDATES[0];
