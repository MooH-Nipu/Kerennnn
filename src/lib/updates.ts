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
    version: '2026.06.10-1',
    title: "What's new",
    changes: [
      '🧠 Smarter confidence scoring: correlated Abuse.ch sources no longer inflate the score, low-trust sources produce softer floors, and MalwareBazaar/GreyNoise signals now trigger hard overrides.',
      '🛠️ Fixed Criminal IP always showing "clean" — it now correctly reads the risk level, so malicious IPs are flagged.',
    ],
  },
  {
    version: '2026.06.09-2',
    title: "What's new",
    changes: [
      '🔍 7 new threat intel sources added: GreyNoise, MalwareBazaar, URLScan.io, Shodan, ThreatFox, Pulsedive, Criminal IP.',
      '⚖️ Source trust weights updated — more reliable sources carry more weight in the confidence score.',
      '🧹 Unconfigured sources no longer appear as "SKIPPED" in scan results.',
    ],
  },
  {
    version: '2026.06.09-1',
    title: "What's new",
    changes: [
      '💾 Tab state is now preserved — inputs and outputs no longer reset when you switch tabs.',
    ],
  },
  {
    version: '2026.06.08-2',
    title: "What's new",
    changes: [
      '🔴 JSON Beautifier now highlights IOCs in red — IPs, domains, URLs, hashes & emails stand out inside the log so you can spot them at a glance. The "Extract IOCs" mode is still there too.',
    ],
  },
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
