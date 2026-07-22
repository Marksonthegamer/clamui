export type Feature = {
  title: string;
  eyebrow: string;
  blurb: string;
  bullets: string[];
  screenshot: string; // under /screenshots/
  alt: string;
  highlight?: boolean;
};

export const features: Feature[] = [
  {
    title: "System security audit",
    eyebrow: "Flagship",
    blurb:
      "Go beyond virus scanning. ClamUI inspects your system's posture the way a Linux-savvy admin would — firewall, MAC (AppArmor/SELinux), SSH hardening, rootkit checks, and more.",
    bullets: [
      "Firewall state + policy review",
      "AppArmor / SELinux enforcement",
      "SSH daemon hardening checks",
      "Rootkit heuristics",
    ],
    screenshot: "/screenshots/audit_view.png",
    alt: "ClamUI system security audit view",
    highlight: true,
  },
  {
    title: "Scan profiles",
    eyebrow: "Reusable",
    blurb:
      "Save the scans you actually run. Quick Scan, Full Scan, Home Folder, or hand-crafted profiles with per-profile exclusions and targets — ready in one click.",
    bullets: [
      "Targets + exclusion globs per profile",
      "Import / export as JSON",
      "Sensible defaults on first run",
    ],
    screenshot: "/screenshots/profile_management.png",
    alt: "ClamUI profile management view",
  },
  {
    title: "Quarantine, verified",
    eyebrow: "Threat handling",
    blurb:
      "Infected files are moved with restrictive permissions and SHA-256 hashed. Restore only if integrity checks pass — no silent tampering.",
    bullets: [
      "SHA-256 integrity verification",
      "SQLite-backed metadata ledger",
      "Secure restore + hard delete",
    ],
    screenshot: "/screenshots/quarantine_view.png",
    alt: "ClamUI quarantine management view",
  },
  {
    title: "History & statistics",
    eyebrow: "Visibility",
    blurb:
      "Paginated scan history with full result dumps, plus a dashboard of what's been caught, when, and where — so you're never guessing.",
    bullets: [
      "Per-scan detail with exportable CSV",
      "Threat category breakdown",
      "Pagination tuned for years of logs",
    ],
    screenshot: "/screenshots/history_view.png",
    alt: "ClamUI scan history view",
  },
  {
    title: "Configured, not configurable-to-death",
    eyebrow: "Preferences",
    blurb:
      "Modular preferences pages surface the ClamAV settings that actually matter — freshclam, on-access (clamonacc), scheduled scans, VirusTotal — without dumping the full clamd.conf on you.",
    bullets: [
      "Auto-detects ClamAV daemon & config paths",
      "Safe permission elevation to apply changes",
      "Scheduled scans via systemd timers or cron",
    ],
    screenshot: "/screenshots/config_view.png",
    alt: "ClamUI configuration view",
  },
  {
    title: "VirusTotal, when you want it",
    eyebrow: "Optional",
    blurb:
      "Enrich detections with a second opinion. API keys live in your system keyring — never in plain-text config. Off by default.",
    bullets: [
      "Keyring-backed API key storage",
      "SHA-256 lookups + optional uploads",
      "Rate-limit aware with retry/backoff",
    ],
    screenshot: "/screenshots/components_view.png",
    alt: "ClamUI components view",
  },
];
