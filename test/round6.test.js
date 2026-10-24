"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { sanitizeText } = require("../src/policy");
const gate = require("../src/gate");
const { generate, scanPack } = require("../src/generate");
const { slugify } = require("../src/util");
const { compoundNames, cases, INJECT } = require("../scripts/fuzz-corpus");
const names = require("./names-corpus");

const V = "Winter" + "25x";

test("B1: labels joined by - _ . or camelCase are labels in names, notes and the gate", () => {
  const secret = [
    ["DB-Password: " + V, V],
    ["db_password: " + V, V],
    ["Master-Passwort: Blau7Haus", "Blau7Haus"],
    ["Wi-Fi-Password: " + V, V],
    ["root-password " + V, V],
    ["Login-PIN: 4821", "4821"],
    ["dbPassword = " + V, V],
    ["API_TOKEN=abc", "abc"],
    ["pwd=tangerine", "tangerine"],
    ["DBpwd: Blau7Haus", "Blau7Haus"],
    ["myPIN=Blau7Haus", "Blau7Haus"],
    ["DBPIN: 4821", "4821"],
    ["PIN: tangerine", "tangerine"],
    ["Zugangscode: Blau7Haus", "Blau7Haus"],
    ["CVV 123", "123"],
    ["sort code 12-34-56", "12-34-56"],
    ["account number 12345678", "12345678"],
    ["pin code: 4821", "4821"],
  ];
  for (const [text, value] of secret) {
    for (const kind of ["name", "note"]) {
      const out = sanitizeText(text, { kind });
      assert.ok(!out.includes(value), `${kind}: ${text} -> ${out}`);
    }
    assert.ok(gate.scanText(text).length > 0, `gate missed: ${text}`);
  }
});

test("B1: ordinary names that merely contain a compound credential word are untouched, in the policy and in the gate", () => {
  for (const n of [
    "DB-Password rotation",
    "Wi-Fi-Password reminder",
    "Master-Passwort Reset",
    "Login-PIN reminder",
    "API-Key expiry check",
    "db_password vault sync",
    "SSH key rotation",
    "Stripe-Token refresher",
  ]) {
    assert.equal(sanitizeText(n), n);
    assert.deepEqual(gate.scanText(n), [], n);
  }
});

test("B1: file names come from the SANITISED name", async () => {
  const wfs = [
    `Login-PIN: 4821`,
    `DB-Password: ${V}`,
    `root-password ${V}`,
  ].map((name, i) => ({
    id: `id-${i}-abcdef`,
    name,
    nodes: [],
    connections: {},
  }));
  const { files } = await generate(wfs, { date: "2026-01-01" });
  for (const f of Object.keys(files)) {
    assert.ok(!/4821|winter|25x/i.test(f), `file name leaks: ${f}`);
    assert.match(f, /^[a-z0-9][a-z0-9.-]*$/);
  }
  assert.ok(
    Object.keys(files).filter((f) =>
      /^(login-pin|db-password|root-password)-h[0-9a-f]{6}\.md$/.test(f),
    ).length >= 2,
  );
});

test("B1: compound generator is in the fuzz corpus and the corpus has both parts", () => {
  const c = compoundNames();
  assert.ok(c.length >= 500, `${c.length}`);
  assert.ok(
    c.some((x) => /^DB-Password: /.test(x.text)) ||
      c.some((x) => /Password/.test(x.text)),
  );
  let n = 0;
  for (const x of cases()) {
    n++;
    void x;
  }
  assert.ok(n > 1900);
});

test("M1: the gate flags ANY value after a credential label (all languages, compounds), but no ordinary name", () => {
  for (const t of [
    "password: tangerine",
    "pwd=tangerine",
    "API_TOKEN=abc",
    "mot de passe : tangerine",
    "пароль: tangerine",
    "kata sandi: tangerine",
    "DB-Password: abc",
    "login: x",
    "token = 1",
  ]) {
    assert.ok(gate.scanText(t).length > 0, `gate missed: ${t}`);
  }
  for (const n of names)
    assert.deepEqual(gate.scanText(n), [], `gate false positive on name: ${n}`);
});

test("M1: a whole pack of the 70+ ordinary names passes the gate", async () => {
  const wfs = names.map((name, i) => ({
    id: `wf-${i}-abcdefgh`,
    name,
    nodes: [{ name: "Step " + name, type: "n8n-nodes-base.noOp" }],
    connections: {},
  }));
  const { files, findings } = await generate(wfs, { date: "2026-01-01" });
  assert.deepEqual(findings, []);
  assert.deepEqual(scanPack(files), []);
});

test("MINOR: generated file names (words + -h<6 hex>) do not trip the gate", async () => {
  const { files, findings } = await generate(
    [
      {
        id: "abc",
        name: `wf17 ${"password: " + V}`,
        nodes: [],
        connections: {},
      },
      { id: "def", name: "密码重置", nodes: [], connections: {} },
    ],
    { date: "2026-01-01" },
  );
  assert.deepEqual(findings, []);
  assert.ok(Object.keys(files).some((f) => /-h[0-9a-f]{6}\.md$/.test(f)));
  assert.deepEqual(
    gate.scanText("see wf17-h809d2d.md and #wf-flow-password-h734a59"),
    [],
  );
});

test("MINOR: Windows reserved names get a suffix; accents transliterate; other scripts fall back to workflow-<hash>", () => {
  const taken = new Set();
  for (const n of ["con", "NUL", "prn", "aux", "COM1", "lpt9"]) {
    const s = slugify(n, taken, n);
    assert.ok(!/^(con|nul|prn|aux|com[1-9]|lpt[1-9])$/.test(s), s);
    assert.match(s, /-wf$/);
  }
  assert.equal(
    slugify("Passwort zurücksetzen", new Set(), "x"),
    "passwort-zurucksetzen",
  );
  assert.match(
    slugify("密码重置", new Set(), "id-1"),
    /^workflow-h[0-9a-f]{6}$/,
  );
  assert.notEqual(
    slugify("密码重置", new Set(), "id-1"),
    slugify("密码重置", new Set(), "id-2"),
  );
});

test("MINOR: new labels (Zugangscode, cvv, pin code, sort code, account number) work", () => {
  for (const [t, v] of [
    ["Zugangscode: Blau7Haus", "Blau7Haus"],
    ["cvv 123", "123"],
    ["cvv: 123", "123"],
    ["PIN code is 4821", "4821"],
    ["sort code 12-34-56", "12-34-56"],
    ["account number: 12345678", "12345678"],
  ]) {
    assert.ok(!sanitizeText(t).includes(v), t);
    assert.ok(gate.scanText(t).length > 0, `gate: ${t}`);
  }
  assert.equal(sanitizeText("Reset PIN"), "Reset PIN");
  assert.equal(
    sanitizeText("Account number format check"),
    "Account number format check",
  );
});

test("README: fuzz numbers are exact, no stale notes line, options table consistent", () => {
  const readme = fs.readFileSync(
    path.join(__dirname, "..", "README.md"),
    "utf8",
  );
  let n = 0;
  for (const x of cases()) {
    n++;
    void x;
  }
  assert.ok(
    readme.includes(`${n} hostile cases`),
    `README should say "${n} hostile cases"`,
  );
  assert.ok(
    readme.includes(`${INJECT.length * 4} injected`),
    `README should say "${INJECT.length * 4} injected"`,
  );
  assert.ok(!/Sticky notes are copied in/.test(readme));
  const rows = readme.split("\n").filter((l) => /^\| `--/.test(l));
  assert.ok(rows.length >= 14);
  assert.ok(
    rows.every((r) => /^\| `[^|]+` \| [^|].* \|$/.test(r)),
    "option rows have two cells",
  );
  assert.match(readme, /one-off check, not part of the test suite/);
});

test('gate: credential type identifiers in tables and tokens spread over cells are not labels', () => {
  assert.deepEqual(gate.scanText('| Groq (SF-01) | httpHeaderAuth | Groq: write script |'), []);
  assert.deepEqual(gate.scanText('| Gemini API Key (X-goog-api-key) | googleSheetsOAuth2Api | HM-01 Hermes Slack Agent (#skynet) |'), []);
  assert.ok(gate.scanText('dbPassword: tangerine').length > 0);
});
