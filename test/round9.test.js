"use strict";
// 1.0.4: the final gate judges a labelled value only inside its own CSV field. A value in the next
// column can no longer complete a label in an earlier, safe name (src/gate.js scanText, csvRows).
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { scanPack, generate } = require("../src/generate");

const HEADER =
  '"workflow","active","service","credential_name","credential_type","nodes"';
const SAFE_NAMES = [
  "Secret Key - Rotation",
  "Credentials - Slack",
  "Password - Reset Flow",
  "Key Accounts: weekly sync",
  "Key Results: Q4 review",
  "Token: refresh job",
  "Secret Sauce - Recipe",
];
const csvRow = (fields) => fields.map((f) => `"${f}"`).join(",");

test("R9 A: the seven documented-safe names pass the gate unchanged (full pipeline)", async () => {
  const base = JSON.parse(
    fs.readFileSync(
      path.join(
        __dirname,
        "..",
        "examples",
        "workflows",
        "01-lead-alerts.json",
      ),
      "utf8",
    ),
  );
  for (const name of SAFE_NAMES) {
    const wf = structuredClone(base);
    wf.name = name;
    const { files, findings } = await generate([wf], { date: "2026-10-26" });
    assert.deepEqual(findings, [], `gate: ${name}`);
    assert.ok(
      files["inventory.csv"].includes(`"${name}"`),
      `verbatim: ${name}`,
    );
  }
});

test("R9 B: a value-shaped token in the NEXT CSV column does not fail an earlier safe name", () => {
  for (const name of SAFE_NAMES) {
    for (const next of [
      "abc123xyz",
      "Zx9Kq2",
      "7f3a9b2c",
      "CRM API key Zx9Kq2",
    ]) {
      const csv = [
        HEADER,
        csvRow([name, "true", "Gmail", next, "gmailOAuth2", "Email"]),
      ].join("\n");
      assert.deepEqual(
        scanPack({ "inventory.csv": csv }),
        [],
        `${name} | ${next}`,
      );
    }
  }
});

test("R9 C: a secret in any single CSV column still trips the gate", () => {
  const secrets = [
    "Password: Winter25x",
    "Token - Sheet Zx9Kq2",
    "Secret: Slack 7f3a9b2c",
  ];
  for (let col = 0; col < 6; col++) {
    for (const secret of secrets) {
      const cells = [
        "Safe Name",
        "true",
        "Gmail",
        "Owner Gmail",
        "gmailOAuth2",
        "Email",
      ];
      cells[col] = secret;
      const csv = [HEADER, csvRow(cells)].join("\n");
      const hits = scanPack({ "inventory.csv": csv });
      assert.ok(hits.length > 0, `column ${col}: ${secret}`);
      assert.equal(hits[0].line, 2, `line of column ${col}`);
    }
  }
});

test("R9 D: quoted CSV fields (doubled quotes, commas) keep their boundaries", () => {
  const csv = [
    HEADER,
    '"Key Accounts: weekly sync","true","Gmail","a ""quoted"", value","gmailOAuth2","x"',
  ].join("\n");
  assert.deepEqual(scanPack({ "inventory.csv": csv }), []);
});

test("R9 E: markdown and HTML still stop a labelled value at the table cell and the tag", () => {
  const md = "| Credentials - Slack | abc123xyz |\n";
  assert.deepEqual(scanPack({ "index.md": md }), []);
  const html = "<td>Token: refresh job</td><td>Zx9Kq2 7f3a9b2c</td>";
  assert.deepEqual(scanPack({ "index.html": html }), []);
});
