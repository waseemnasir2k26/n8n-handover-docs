"use strict";
// Whole-pipeline usefulness test: the CLI (policy -> render -> final gate -> write) over ordinary
// must exit 0 and not change any name. Dash forms ("Label - Thing") and colon forms with WEAK labels
// ("Credentials: Google Sheets", "Token: refresh job") are ordinary names; a single plain word after a weak
// colon is a value ("Token: Zebra", see test/value-rule.test.js). The rule is in README limits.
const test = require("node:test");
const assert = require("node:assert/strict");
const cp = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { sanitizeText } = require("../src/policy");

const BIN = path.join(__dirname, "..", "bin", "n8n-handover-docs.js");

const NAMES = [
  "Credentials: Google Sheets",
  "Credentials: Slack Alerts",
  "Token: refresh job",
  "API Key: Customer Rotation",
  "Auth: Google Callback",
  "Login: Daily Alerts",
  "Key Accounts: Alice Smith",
  "Secret Santa: Alice Smith",
  "Credentials - Slack",
  "Credentials - Google Sheets",
  "Credentials - Gmail Drafts",
  "Credentials - Slack Alerts",
  "Credentials - HubSpot CRM",
  "Credentials - Notion Sync",
  "Credentials - Airtable Base",
  "Credentials - Stripe Webhook",
  "Credentials - Postgres Reports",
  "Credentials - Shopify Orders",
  "Credentials - Zoom Meetings",
  "Credentials - Trello Boards",
  "Credentials - Sheets Export",
  "Credential - Slack Alerts",
  "API Key - Rotation",
  "API Key - Customer Portal",
  "API Key - Calendly Booking",
  "API Key - Weekly Report",
  "Token - Usage Report",
  "Token - Refresh Log",
  "Token - Lead Enrichment",
  "Token - Daily Digest",
  "Password - Reset Flow",
  "Password - Reset Email",
  "Password - Welcome Mail",
  "Password - Expiry Warning",
  "Secret - Manager Sync",
  "Secret - Vault Backup",
  "Secret - Rotation Reminder",
  "Secret - Scheduled Export",
  "Auth - Callback",
  "Auth - Google Login",
  "Auth - Webhook Relay",
  "Auth - Refresh Sync",
  "PIN Code Generator - Sheet",
  "PIN - Pad Lock Sorter",
  "Login - Alerts",
  "Login - Reminder Emails",
  "Login - Welcome Series",
  "Login - Daily Summary",
];

const workflowFor = (name, i) => ({
  id: `usefulness-${i}`,
  name,
  active: true,
  nodes: [
    {
      id: `n-${i}`,
      name,
      type: "n8n-nodes-base.noOp",
      typeVersion: 1,
      position: [0, 0],
      parameters: {},
    },
  ],
  connections: {},
});

test("usefulness corpus has 48 ordinary names (40 dash forms, 8 colon forms) and the name policy leaves each one unchanged", () => {
  assert.equal(NAMES.length, 48);
  for (const n of NAMES) assert.equal(sanitizeText(n), n, n);
});

test("usefulness pipeline: the CLI exits 0 on a folder of those names and writes every name unchanged", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "usefulness-"));
  try {
    const src = path.join(root, "in");
    const out = path.join(root, "out");
    fs.mkdirSync(src);
    NAMES.forEach((n, i) =>
      fs.writeFileSync(
        path.join(src, `wf-${String(i).padStart(2, "0")}.json`),
        JSON.stringify(workflowFor(n, i)),
      ),
    );
    const r = cp.spawnSync(
      process.execPath,
      [
        BIN,
        "--from-dir",
        src,
        "--out",
        out,
        "--title",
        "Usefulness",
        "--date",
        "2026-01-01",
        "--no-gitleaks",
        "--offline",
      ],
      { encoding: "utf8", timeout: 120000 },
    );
    assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
    const index = fs.readFileSync(path.join(out, "index.md"), "utf8");
    assert.doesNotMatch(index, /\[redacted\]/);
    for (const n of NAMES)
      assert.ok(index.includes(n), `name not written unchanged: ${n}`);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("final gate: plain-letter names after a dash or a WEAK label are names; strong labels with any value, and weak labels with a value-looking token, are blocked", () => {
  const { scanText } = require("../src/gate");
  for (const ok of [
    "Credentials - Slack",
    "Credentials - Slack.",
    "Credentials - Google Sheets",
    "<td>Credentials - Slack</td><td>unknown</td>",
    '"Credentials - Slack","",""',
    "Credentials: Google Sheets",
    "Token: refresh job",
    "API Key: Customer Rotation",
    "Auth: Google Callback",
    "Login: Daily Alerts",
  ])
    assert.deepEqual(scanText(ok), [], ok);
  for (const bad of [
    "password: tangerine",
    "password: Winter25x",
    "secret = bluesky",
    "Credentials - ghp_abc123XYZ",
    "Credentials: Slack2024!",
    "Token: ghp_abc123XYZ",
    "API Key: sk-live-abc123",
    "Token: Zebra",
    "Access Token: zebra",
    "Secret - tangerine",
  ])
    assert.ok(scanText(bad).length > 0, bad);
});
