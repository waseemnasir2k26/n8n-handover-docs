"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { sanitizeText } = require("../src/policy");
const gate = require("../src/gate");
const { generate, scanPack } = require("../src/generate");

// 1.0.3: the dash and colon rules check EVERY token after the label, not only the first one.
test("R8 A: a value hidden behind an allow-listed noun is redacted", () => {
  for (const [name, value] of [
    ["Password - Slack abc123xyz", "abc123xyz"],
    ["Token - Sheet Zx9Kq2", "Zx9Kq2"],
    ["Secret: Slack 7f3a9b2c", "7f3a9b2c"],
    ["Password - Slack  abc123xyz", "abc123xyz"],
    ["Password - Winter25x Slack", "Winter25x"],
    ["Key Accounts - Tangerine abc123", "abc123"],
    ["PIN Code Generator - Sheet Zx9", "Zx9"],
  ]) {
    assert.ok(!sanitizeText(name).includes(value), `policy: ${name}`);
    assert.ok(!gate.scanText(sanitizeText(name)).length, `gate: ${name}`);
  }
});

test("R8 B: ordinary names stay (all tokens safe words, allow-list rule for one token)", () => {
  for (const name of [
    "Password - Reset Flow",
    "Credentials - Slack",
    "Key Accounts: weekly sync",
    "Password - Slack Reset Flow",
    "Secret Key - Rotation",
    "PIN Code Generator - Sheet",
    "Credentials - CRM Sheet",
    "Token - Usage Report",
  ]) {
    assert.equal(sanitizeText(name), name, name);
    assert.deepEqual(gate.scanText(name), [], name);
  }
});

test("R8 C: a single token after a dash still needs the allow-list", () => {
  assert.match(sanitizeText("Password - Zebra"), /\[redacted\]/);
  assert.match(sanitizeText("Key Accounts - Tangerine"), /\[redacted\]/);
});

test("R8 D: the whole workflow name with a hidden value never reaches any output file", async () => {
  for (const [name, value] of [
    ["Password - Slack abc123xyz", "abc123xyz"],
    ["Token - Sheet Zx9Kq2", "Zx9Kq2"],
    ["Secret: Slack 7f3a9b2c", "7f3a9b2c"],
  ]) {
    const wfs = [
      {
        id: "r8" + value.length,
        name,
        nodes: [{ name: "Step", type: "n8n-nodes-base.noOp" }],
        connections: {},
      },
    ];
    const { files, findings } = await generate(wfs, { date: "2026-01-01" });
    assert.deepEqual(scanPack(files), [], name);
    for (const [f, c] of Object.entries(files)) {
      assert.ok(!f.includes(value), `${f} leaks ${value}`);
      assert.ok(!c.includes(value), `${name}: ${value} leaked into ${f}`);
    }
    assert.ok(Array.isArray(findings));
  }
});
