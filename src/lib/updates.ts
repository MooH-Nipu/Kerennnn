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
    version: '2026.06.14-1',
    title: "What's new",
    changes: [
      '⚡ Re-scanning an already-seen IP no longer re-calls the other threat-intel sources — it reuses the saved correlation just like VirusTotal, so repeat scans cost zero extra API calls.',
      '📊 API Usage tab refined: calls per user and outcomes per user (all sources combined), VirusTotal usage over time, and the recent-calls list trimmed to the latest 10.',
      '🔑 The usage "key" column now shows whichever source\'s API key served each call, not just VirusTotal.',
      '✨ Tidier, right-sized buttons on the API Usage, CVE Lookup and ATT&CK tabs.',
    ],
  },
  {
    version: '2026.06.13-2',
    title: "What's new",
    changes: [
      '⚙️ New Settings tab — set your own malicious-IOC alert webhook (Slack/Teams/Discord) and confidence threshold. Each user gets their own alerts.',
      '📊 New admin tab: API Usage — visualize threat-intel API consumption per user, by service, outcome (OK / rate-limited / error), VT key & over time.',
      '🧹 Retired GreyNoise, Shodan, Pulsedive & MalwareBazaar from the scan engine — confidence scoring now relies on the more reliable core sources.',
    ],
  },
  {
    version: '2026.06.13-1',
    title: "What's new",
    changes: [
      '🎯 New tab: MITRE ATT&CK Lookup — search techniques by ID (T1059) or keyword for tactics, detection guidance & platforms.',
      '🛡️ New tab: CVE Lookup — search a CVE ID or keyword for CVSS score, severity, vector & references (NVD).',
      '🔭 Passive DNS panel on IP & domain scan cards — pivot to related hosts and subdomains.',
      '📜 Certificate History (crt.sh) panel on domain scan cards — surfaces subdomains & infrastructure history.',
      '🚨 Optional Slack/Teams/Discord alert when a scan comes back MALICIOUS.',
    ],
  },
  {
    version: '2026.06.11-2',
    title: "What's new",
    changes: [
      '🧹 Removed ThreatFox and Criminal IP — they were unreliable and have been dropped from the scan engine.',
      '⚡ Scan cards now appear as soon as VirusTotal responds — threat intel loads in the background for faster scanning.',
      '🛠️ TI source errors are shown inline below the source row.',
      '🧠 Smarter confidence scoring: correlated Abuse.ch sources no longer inflate the score, and MalwareBazaar/GreyNoise signals trigger hard overrides.',
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
