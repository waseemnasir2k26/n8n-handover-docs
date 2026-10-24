"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { sanitizeText } = require("../src/policy");
const gate = require("../src/gate");
const { generate, scanPack } = require("../src/generate");
const { analyzeWorkflow } = require("../src/parse");
const labels = require("../src/labels");
const { cases, INJECT, EXTRA } = require("../scripts/fuzz-corpus");
const names = require("./names-corpus");

const UUID = "3f2b8c1e-9d4a-4f6b-8a1c-0e5d7b2a9c11";

test("webhook paths (UUID-like) are masked by their own rule and never counted as names", async () => {
  const wfs = Array.from({ length: 15 }, (_, i) => ({
    name: `Clean workflow ${i}`,
    nodes: [
      {
        name: "Hook",
        type: "n8n-nodes-base.webhook",
        webhookId: "w",
        parameters: { path: UUID.replace("3f2b", `${i}f2b`) },
      },
    ],
    connections: {},
  }));
  const { files, items } = await generate(wfs, { date: "2026-01-01" });
  assert.equal(
    items.reduce((n, { m }) => n + m.redactedNames, 0),
    0,
  );
  assert.match(files["index.md"], /0 name\(s\) were partly replaced/);
  assert.match(files["index.md"], /Webhook paths shortened \| 15/);
  assert.ok(!Object.values(files).join("\n").includes(UUID.slice(5)));
  assert.equal(
    analyzeWorkflow({ nodes: [{ name: 'h', type: 'n8n-nodes-base.webhook', webhookId: 'w', parameters: { path: 'customer-intake-endpoint' } }] }, { showWebhookPaths: true }).webhooks[0].path,
    'customer-intake-endpoint',
  );
});

test("numeric PINs and codes after a code label are redacted; a label alone is not", () => {
  const secret = [
    ["pin: 4821", "4821"],
    ["my pin is 4821", "4821"],
    ["door code: 4821", "4821"],
    ["gate code is 4821", "4821"],
    ["safe code 4821", "4821"],
    ["Reset PIN 482193", "482193"],
    ["PIN code: four eight two one", "four eight two one"],
    ["alarm code is tango alpha", "tango alpha"],
    ["otp 835512", "835512"],
    ["security code: 7731", "7731"],
    ["verification code is 902144", "902144"],
    ["access code 482 193", "482 193"],
    ["pin:4821", "4821"],
  ];
  for (const [text, value] of secret) {
    for (const kind of ["name", "note"]) {
      const out = sanitizeText(text, { kind });
      assert.ok(!out.includes(value), `${kind}: ${text} -> ${out}`);
      assert.match(out, /\[redacted\]/);
    }
    assert.ok(gate.scanText(text).length > 0, `gate missed: ${text}`);
  }
  for (const ok of [
    "Reset PIN",
    "Pin message to channel",
    "Pin 3 messages",
    "Send OTP email",
    "Door code reminder",
    "Alarm code review",
  ]) {
    assert.equal(sanitizeText(ok), ok);
    assert.deepEqual(gate.scanText(ok), [], ok);
  }
});

test("emoji labels act as credential labels in names, tags and notes", () => {
  for (const [text, value] of [
    ["\u{1F511} hunter22", "hunter22"],
    ["\u{1F512}hunter22", "hunter22"],
    ["\u{1F510}: winter phrase", "winter phrase"],
    ["\u{1F5DD}️ Tr0ub4dor", "Tr0ub4dor"],
    ["\u{1F511}: hunter22", "hunter22"],
  ]) {
    for (const kind of ["name", "note"])
      assert.ok(
        !sanitizeText(text, { kind }).includes(value),
        `${kind}: ${text}`,
      );
    assert.ok(gate.scanText(text).length > 0, `gate missed: ${text}`);
  }
  for (const ok of [
    "\u{1F511} Key account sync",
    "\u{1F512} Locked account report",
    "\u{1F510} Rotate keys monthly",
  ])
    assert.equal(sanitizeText(ok), ok);
});

test("every language in the label list works in the NAME policy (not only notes) and in the gate", () => {
  assert.ok(labels.LANGUAGES.length >= 16);
  for (const [lang, def] of Object.entries(labels.BY_LANG)) {
    for (const word of def.strong) {
      if (/^(sk|pass|pw|pwd)$/.test(word)) continue;
      const label =
        word === "motdepasse"
          ? "mot de passe"
          : word === "katasandi"
            ? "kata sandi"
            : word === "klé"
              ? word
              : word;
      const spaced =
        lang === "Vietnamese" && word.startsWith("mật") ? "mật khẩu" : label;
      const text = `${spaced}: Zq8wRt5Yu3`;
      assert.ok(!sanitizeText(text).includes("Zq8wRt5Yu3"), `${lang}: ${text}`);
      assert.ok(gate.scanText(text).length > 0, `gate ${lang}: ${text}`);
    }
  }
  for (const text of [
    "Kennwort: Sommer2026x",
    "mật khẩu: Mua2026xy",
    "รหัสผ่าน: ฝน123",
  ]) {
    assert.ok(!/2026x|2026xy|123$/.test(sanitizeText(text)), text);
  }
});

test("README language list is generated from the code", () => {
  const readme = fs.readFileSync(
    path.join(__dirname, "..", "README.md"),
    "utf8",
  );
  const m = /<!-- langs:start -->([\s\S]*?)<!-- langs:end -->/.exec(readme);
  assert.ok(m, "README needs the langs markers");
  assert.equal(m[1].trim(), labels.LANGUAGES.join(", "));
});

test("README states the exact fuzz numbers from the corpus", () => {
  const readme = fs.readFileSync(
    path.join(__dirname, "..", "README.md"),
    "utf8",
  );
  let n = 0;
  for (const c of cases()) {
    n++;
    void c;
  }
  assert.ok(
    readme.includes(`${n} hostile cases`),
    `README should say "${n} hostile cases"`,
  );
  assert.ok(
    readme.includes(`${INJECT.length * 4} injected`),
    `README should say "${INJECT.length * 4} injected"`,
  );
  assert.ok(Object.keys(EXTRA).length > 60);
});

test("fuzz: injected-after-render cases are all stopped by the final gate (non-zero, proven)", async () => {
  const base = (
    await generate(
      [
        {
          name: "ok",
          nodes: [{ name: "a", type: "n8n-nodes-base.noOp" }],
          connections: {},
        },
      ],
      { date: "2026-01-01" },
    )
  ).files;
  assert.deepEqual(scanPack(base), []);
  let stopped = 0;
  const missed = [];
  for (const payload of INJECT) {
    for (const file of ["index.md", "ok.md", "index.html", "inventory.csv"]) {
      const files = { ...base };
      files[file] +=
        file === "index.html" ? `\n<p>${payload}</p>\n` : `\n${payload}\n`;
      if (scanPack(files).some((f) => f.file === file)) stopped++;
      else missed.push(`${file}: ${payload}`);
    }
  }
  assert.deepEqual(missed, []);
  assert.ok(stopped >= 100);
});

test('every generated pack starts with a "what was redacted" table and the best-effort banner', async () => {
  const { files } = await generate(
    [
      {
        name: `password: ${"Winter" + "2026!!"}`,
        nodes: [
          {
            name: "S",
            type: "n8n-nodes-base.stickyNote",
            parameters: { content: "x" },
          },
        ],
        connections: {},
      },
    ],
    { date: "2026-01-01" },
  );
  const idx = files["index.md"];
  assert.match(
    idx,
    /Best-effort: read every pack before you send it to a client/,
  );
  assert.match(idx, /## What was redacted or hidden/);
  assert.match(idx, /Names with a value replaced by \\\[redacted\\\] \| 1/);
  assert.match(idx, /Sticky notes hidden \| 1/);
  assert.ok(idx.indexOf("What was redacted") < idx.indexOf("## Workflows"));
  assert.match(files["index.html"], /What was redacted or hidden/);
});

test("usefulness corpus still has 0 false redactions", () => {
  assert.deepEqual(
    names.filter((n) => sanitizeText(n) !== n),
    [],
  );
});
