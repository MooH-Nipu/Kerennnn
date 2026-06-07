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
    version: '2026.06.08-1',
    title: "What's new",
    changes: [
      '🌐 The whole app is now in English.',
      '🧹 JSON Beautifier now auto-formats as you type — no button needed. Toggle Beautify/Minify; the output box fills the full width.',
      '🔎 New "Extract IOCs" mode in the JSON tab — pull IPs, domains, URLs, hashes & emails out of any text or log (defang-aware).',
      '👤 User Management: you can now change a user\'s username & password — click "Edit" on a user card.',
    ],
  },
  {
    version: '2026.06.06-1',
    title: "What's new",
    changes: [
      '🧭 Reorder tabs however you like — just drag a tab in the navigation to where you want it. Saved automatically & synced to your account.',
      '🧹 New tab: JSON Beautifier — beautify or minify JSON, plus NDJSON log support.',
      '🔍 "Deep Analysis" is now available for Domains & Hashes, not just IPs.',
    ],
  },
];

// Newest entry drives the toast.
export const LATEST_UPDATE: UpdateEntry = UPDATES[0];
