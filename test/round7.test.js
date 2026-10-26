"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { sanitizeText } = require("../src/policy");
const gate = require("../src/gate");
const { generate, scanPack } = require("../src/generate");

const V = "Winter" + "25x";

test("R7 A: label variants (trailing digits, plural s) redact the value in every output file", async () => {
  const cases = [
    ["password1: " + V, V],
    ["Passwords: " + V, V],
    ["pass2: " + V, V],
    ["pw1: " + V, V],
    ["PIN2: 482193", "482193"],
    ["apikey2: " + V, V],
  ];
  for (const [name, value] of cases) {
    assert.ok(!sanitizeText(name).includes(value), `policy: ${name}`);
    const wfs = [
      {
        id: "r7-" + value.length + "-" + name.length,
        name,
        nodes: [{ name: "Step " + name, type: "n8n-nodes-base.noOp" }],
        connections: {},
      },
    ];
    const { files } = await generate(wfs, { date: "2026-01-01" });
    for (const [f, c] of Object.entries(files)) {
      assert.ok(!f.includes(value), `file name leaks ${value}: ${f}`);
      assert.ok(!c.includes(value), `${name}: ${value} leaked into ${f}`);
    }
  }
});

test("R7 B: a dash between a label and a plain word is prose, not a gate block", async () => {
  const names = [
    "Password - reset email",
    "Token - refresh job",
    "API key - rotation reminder",
    "Auth - callback handler",
    "PIN - code generator",
    "Secret - Santa draw",
    "Credentials - Slack",
  ];
  for (const n of names) {
    assert.equal(sanitizeText(n), n, n);
    assert.deepEqual(gate.scanText(n), [], n);
  }
  const wfs = names.map((name, i) => ({
    id: `r7b-${i}-abcdef`,
    name,
    nodes: [],
    connections: {},
  }));
  const { files, findings } = await generate(wfs, { date: "2026-01-01" });
  assert.deepEqual(findings, []);
  assert.deepEqual(scanPack(files), []);
  const all = Object.values(files).join("\n");
  for (const n of names) assert.ok(all.includes(n), `name dropped: ${n}`);
});

test("R7 B: values after a colon or with digits/symbols stay blocked", () => {
  for (const t of ["password: " + V, "Token - ghp_abc123XYZ"]) {
    assert.ok(gate.scanText(t).length > 0, `gate missed: ${t}`);
    assert.ok(!sanitizeText(t).includes(V) && !sanitizeText(t).includes("ghp_abc123XYZ"), t);
  }
});
