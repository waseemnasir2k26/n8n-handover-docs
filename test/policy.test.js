"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { sanitizeText, sanitizeIdent, normalise } = require("../src/policy");
const gate = require("../src/gate");
const { generate, scanPack } = require("../src/generate");
const { analyzeWorkflow } = require("../src/parse");
const { mdEsc } = require("../src/util");

const V = "Winter" + "2026!!";

test("normalise: NFKC, zero-width, entities, %-encoding, markdown wrappers, newlines", () => {
  assert.equal(normalise("ｐａss"), "pass");
  assert.equal(normalise("pa​ss­﻿word"), "password");
  assert.equal(normalise("a&#58; b&colon; c&amp;d"), "a: b: c&d");
  assert.equal(normalise("pass%77ord%3A%20x"), "password: x");
  assert.equal(normalise("**password** | `x`"), "password x");
  assert.equal(normalise("a\n\n  b"), "a b");
});

test("name policy: credential words, tokens, hex, base64, confusables are redacted; plain names survive", () => {
  const bad = [
    `password: ${V}`,
    `pаssword ${V}`,
    `ραssword ${V}`,
    `login: bob / ${V}`,
    `api key is ${"8f3a9c1d" + "2e7b4a60"}`,
    `x ${"a1b2c3d4".repeat(3)} y`,
    "c2stcHJvai1BQkNERUZHSDEyMzQ1Njc4Wlpa",
    "s e c r e t: abc",
    "drowssap " + V,
    `p4ssw0rd ${V}`,
  ];
  for (const b of bad) {
    const out = sanitizeText(b);
    assert.ok(out.includes("[redacted]"), `kept: ${b} -> ${out}`);
    assert.ok(!out.includes(V) && !out.includes("8f3a9c1d"), out);
  }
  const good = [
    "Lead alerts (daily)",
    "LG-04 Maps Harvest",
    "Send invoice reminders",
    "Weekly report 2026-10-25",
    "CRM API key",
    "Gmail OAuth",
    "Check Slack token",
    "Stripe read-only key",
  ];
  for (const g of good) assert.equal(sanitizeText(g), g);
});

test("a password word assigned a plain phrase redacts the phrase", () => {
  assert.equal(sanitizeText("my password is horse battery staple"), "my password is [redacted]");
  assert.equal(sanitizeText("my key is horse battery staple"), "my key is [redacted] battery staple");
});

test('identifiers: camelCase credential types stay, anything with spaces or secrets becomes "custom"', () => {
  for (const ok of [
    "googleSheetsOAuth2Api",
    "httpHeaderAuth",
    "n8n-nodes-base.httpRequest",
    "@n8n/n8n-nodes-langchain.agent",
    "SIGNING_SECRET",
  ])
    assert.equal(sanitizeIdent(ok), ok);
  for (const bad of [
    "pass: x1",
    "AKIA" + "IOSFODNN7EXAMPLE",
    "pass__Zq8wRt5Yu",
    "a b",
    "x".repeat(200),
    "hunter2hunter2xyz_is_the_password",
  ])
    assert.equal(sanitizeIdent(bad), "custom", bad);
});

test("sticky notes are hidden by default and counted; --include-notes includes them redacted", async () => {
  const wf = {
    name: "N",
    nodes: [
      {
        name: "S",
        type: "n8n-nodes-base.stickyNote",
        parameters: {
          content: `Runs nightly. password: ${V}. Owner: jane@example.test`,
        },
      },
    ],
    connections: {},
  };
  const def = analyzeWorkflow(wf);
  assert.equal(def.hiddenNotes, 1);
  assert.deepEqual(def.notes, []);
  const inc = analyzeWorkflow(wf, { includeNotes: true });
  assert.equal(inc.notes.length, 1);
  assert.ok(!inc.notes[0].includes(V) && !inc.notes[0].includes("jane@"));
  const { files } = await generate([wf], { date: "2026-01-01" });
  assert.match(
    files["index.md"],
    /1 sticky note\(s\) hidden \(use --include-notes/,
  );
  assert.ok(!Object.values(files).join("").includes(V));
});

test("redacted names are counted", () => {
  const m = analyzeWorkflow({
    name: `password: ${V}`,
    nodes: [{ name: "ok", type: "n8n-nodes-base.noOp" }],
    connections: {},
  });
  assert.ok(m.redactedNames >= 1);
  assert.equal(m.name.includes(V), false);
});

test("gate is independent: it catches tokens, decoded variants and credential-word+value", () => {
  const hit = (t) => gate.scanText(t).length > 0;
  assert.ok(hit(`token ${V}`));
  assert.ok(hit("blob a3f5c9d2e1b04a7788c6d5e4f3a2b1c0"));
  assert.ok(
    hit("c2VjcmV0cGFzc3dvcmQ5OTk5OTk5OTk5OQ=="),
    'base64 of "secretpassword9999..."',
  );
  assert.ok(hit("x api_key%3DSUPERSECRETVALUE99 y"));
  assert.ok(hit("password Zq8wRt5Yu!"));
  assert.ok(
    !hit(
      "Lead alerts (daily) runs every day at 08:00, see lead-alerts-daily.md and googleSheetsOAuth2Api",
    ),
  );
  assert.ok(
    !hit(
      "Token expired, key rotated, or header/auth settings changed (often shown as 401 or 402)",
    ),
  );
});

test("final scan catches an injected leak in every output format", async () => {
  const { files } = await generate(
    [{ name: "ok", nodes: [], connections: {} }],
    { date: "2026-01-01" },
  );
  assert.deepEqual(scanPack(files), []);
  const bad = { ...files };
  bad["index.md"] += `\npassword: ${V}\n`;
  bad["index.html"] +=
    `\n<p>Authorization: Token ${"AuthTok" + "Canary8842xx"}</p>\n`;
  bad["inventory.csv"] +=
    `"x","","","","","blob ${"Qw3rTy" + "Ui0pAs" + "Df7gHj"}"\r\n`;
  const found = scanPack(bad);
  assert.deepEqual([...new Set(found.map((f) => f.file))].sort(), [
    "index.html",
    "index.md",
    "inventory.csv",
  ]);
  assert.ok(!JSON.stringify(found).includes(V));
});

test("gitleaks pass runs when available and reports file:line without values", async () => {
  if (!gate.gitleaksAvailable()) return;
  const files = {
    "a.md": `token ${"ghp_" + "x7Kp2mQ9vL4n" + "B8cD1fG6hJ3sT5wY0zA2eR9u"} end
`,
    "b.md": "clean\n",
  };
  const r = gate.runGitleaks(files);
  assert.equal(r.ran, true);
  assert.ok(r.findings.length >= 1);
  assert.ok(r.findings.every((f) => f.file && f.kind.startsWith("gitleaks")));
  assert.ok(!JSON.stringify(r.findings).includes("x7Kp2mQ9vL4n"));
  assert.deepEqual(gate.runGitleaks({ "c.md": "nothing here\n" }).findings, []);
});

test("CLI exits 3 and writes nothing when the final gate finds something; --allow-findings overrides", async () => {
  const gen = require("../src/generate");
  const cliPath = require.resolve("../src/cli");
  const orig = gen.generate;
  gen.generate = async () => ({
    files: { "index.md": "x\n" },
    items: [],
    warnings: [],
    findings: [
      {
        file: "index.md",
        line: 1,
        kind: "credential word followed by a value",
        source: "builtin",
      },
    ],
  });
  delete require.cache[cliPath];
  try {
    const { main } = require("../src/cli");
    const src = fs.mkdtempSync(path.join(os.tmpdir(), "f3src-"));
    const out = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), "f3out-")),
      "pack",
    );
    fs.writeFileSync(
      path.join(src, "a.json"),
      JSON.stringify({ name: "a", nodes: [], connections: {} }),
    );
    const errs = [];
    const io = { out: () => {}, err: (s) => errs.push(s) };
    assert.equal(
      await main(["--from-dir", src, "--out", out, "--no-gitleaks"], {}, io),
      3,
    );
    assert.ok(!fs.existsSync(out));
    assert.match(errs.join("\n"), /index\.md:1/);
    assert.equal(
      await main(
        ["--from-dir", src, "--out", out, "--no-gitleaks", "--allow-findings"],
        {},
        io,
      ),
      0,
    );
    assert.ok(fs.existsSync(path.join(out, "index.md")));
  } finally {
    gen.generate = orig;
    delete require.cache[cliPath];
  }
});

test("missing --from-dir folder gives a clean message", async () => {
  const { main } = require("../src/cli");
  const errs = [];
  const code = await main(
    ["--from-dir", path.join(os.tmpdir(), "no-such-folder-xyz")],
    {},
    { out: () => {}, err: (s) => errs.push(s) },
  );
  assert.equal(code, 1);
  assert.match(errs.join(""), /Folder not found: /);
  assert.ok(!/scandir|ENOENT/.test(errs.join("")));
});

test("webhook paths masked by default; full with showWebhookPaths; method/auth/response are allowlisted", () => {
  const wf = {
    nodes: [
      {
        name: "h",
        type: "n8n-nodes-base.webhook",
        webhookId: "w",
        parameters: {
          path: "customer-intake-endpoint",
          httpMethod: "POST",
          authentication: "headerAuth",
        },
      },
    ],
  };
  assert.equal(analyzeWorkflow(wf).webhooks[0].path, "cust…");
  assert.equal(
    analyzeWorkflow(wf, { showWebhookPaths: true }).webhooks[0].path,
    "customer-intake-endpoint",
  );
  const odd = analyzeWorkflow({
    nodes: [
      {
        name: "h",
        type: "n8n-nodes-base.webhook",
        parameters: {
          path: "x",
          httpMethod: "AKIA" + "IOSFODNN7EXAMPLE",
          authentication: "pass 123",
          responseMode: "hunter2",
        },
      },
    ],
  });
  assert.equal(odd.webhooks[0].method, "CUSTOM");
  assert.equal(odd.webhooks[0].auth, "custom");
  assert.equal(odd.webhooks[0].responseMode, "custom");
});

test("contacts: hidden in notes by default; names/tags only with redactContacts; keepContacts opts out", () => {
  const wf = {
    name: "Flow jane.doe@example.test",
    nodes: [
      {
        name: "S",
        type: "n8n-nodes-base.stickyNote",
        parameters: {
          content: "mail jane.doe@example.test call +62 812 3456 7890",
        },
      },
    ],
    connections: {},
  };
  const d = analyzeWorkflow(wf, { includeNotes: true });
  assert.ok(
    !d.notes.join(" ").includes("jane.doe") &&
      !d.notes.join(" ").includes("812 3456"),
  );
  assert.ok(d.name.includes("jane.doe"));
  assert.ok(
    !analyzeWorkflow(wf, { redactContacts: true }).name.includes("jane.doe"),
  );
  assert.ok(
    analyzeWorkflow(wf, { includeNotes: true, keepContacts: true })
      .notes.join(" ")
      .includes("jane.doe"),
  );
});

test("javascript:/data: schemes are neutralised in markdown text", async () => {
  assert.ok(!/javascript:/i.test(mdEsc("click javascript:alert(1) now")));
  assert.ok(!/data\s*:/i.test(mdEsc("data:text/html;base64,PHNjcmlwdD4=")));
});

test("--diagram-fallback shows the reason and loads no script", async () => {
  const a = (
    await generate(
      [
        {
          name: "x",
          nodes: [{ name: "a", type: "n8n-nodes-base.noOp" }],
          connections: {},
        },
      ],
      { date: "2026-01-01", diagramFallback: true },
    )
  ).files["index.html"];
  assert.match(a, /Diagram shown as text: --diagram-fallback was used/);
  assert.ok(!/<script/.test(a));
});

test("header date is local with a time zone when --date is not given", async () => {
  const { files } = await generate(
    [{ name: "x", nodes: [], connections: {} }],
    {},
  );
  assert.match(
    files["index.md"],
    /Generated \d{4}-\d{2}-\d{2} \d{2}:\d{2} \(.+\)\./,
  );
});
