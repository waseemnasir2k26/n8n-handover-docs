"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { sanitizeText, sanitizeIdent } = require("../src/policy");
const gate = require("../src/gate");
const { generate } = require("../src/generate");
const { analyzeWorkflow } = require("../src/parse");
const names = require("./names-corpus");

const wfOf = (name) => ({
  id: `id-${name}`,
  name,
  nodes: [{ name: "a", type: "n8n-nodes-base.noOp" }],
  connections: {},
});

test("usefulness corpus: ordinary names, 0 false redactions", () => {
  assert.ok(names.length >= 73);
  const redacted = names.filter((n) => sanitizeText(n) !== n);
  assert.deepEqual(redacted, []);
});

test("usefulness: a pack of those names has one distinct row and file name per name, none called redacted-N", async () => {
  const { files, items } = await generate(names.map(wfOf), {
    date: "2026-01-01",
  });
  assert.equal(new Set(items.map((i) => i.m.name)).size, names.length);
  const mdFiles = Object.keys(files).filter(
    (f) => f.endsWith(".md") && f !== "index.md",
  );
  assert.equal(mdFiles.length, names.length);
  assert.ok(!mdFiles.some((f) => /redacted/.test(f)));
  assert.match(files["index.md"], /0 name\(s\) were partly replaced/);
});

test("credential word alone is not a secret; a value after it is the only thing redacted", () => {
  assert.equal(sanitizeText("Send Token Report"), "Send Token Report");
  assert.equal(
    sanitizeText(
      "token: " + "ghp_" + "x7Kp2mQ9vL4n" + "B8cD1fG6hJ3sT5wY0zA2eR9u",
    ),
    "token: [redacted]",
  );
  assert.equal(
    sanitizeText("Call CRM api_key=" + "Zq8wRt5Yu3Kp9mX2"),
    "Call CRM api_key=[redacted]",
  );
  assert.equal(
    sanitizeText("Nightly backup password: " + "Winter" + "2026!! then email"),
    "Nightly backup password: [redacted] then email",
  );
  assert.equal(
    sanitizeText("Whiskey stock password is horse battery staple"),
    "Whiskey stock password is [redacted]",
  );
});

test("whole-name short secrets are redacted; ordinary one-word names are not", () => {
  for (const s of ["k9x!2q", "hunter22", "Zq7#mP4x"])
    assert.equal(sanitizeText(s), "[redacted]", s);
  for (const ok of [
    "Hotpot",
    "Gmail2",
    "Q3-2026",
    "v2.1.3",
    "Auth0",
    "n8n",
    "S3",
    "GPT4",
  ])
    assert.equal(sanitizeText(ok), ok, ok);
});

test("multilingual credential labels (zh ru ar hi ja ko es fr de pt tr id ur) hide the value in notes and names", () => {
  const cases = [
    ["密码：蓝天白云88", "蓝天白云88"],
    ["密码是蓝天白云88", "蓝天白云88"],
    ["пароль: Лето2026", "Лето2026"],
    ["كلمة السر: شمس٢٠٢٦", "شمس٢٠٢٦"],
    ["पासवर्ड: सूरज99", "सूरज99"],
    ["パスワード: さくら77", "さくら77"],
    ["비밀번호: 하늘123", "하늘123"],
    ["contraseña: Verano2026x", "Verano2026x"],
    ["mot de passe: Ete2026xy", "Ete2026xy"],
    ["Passwort: Sommer2026x", "Sommer2026x"],
    ["senha: Verao2026x", "Verao2026x"],
    ["şifre: Yaz2026xy", "Yaz2026xy"],
    ["kata sandi: Musim2026x", "Musim2026x"],
    ["پاسورڈ: گرمی99", "گرمی99"],
  ];
  for (const [text, secret] of cases) {
    for (const kind of ["name", "note"]) {
      const out = sanitizeText(text, { kind });
      assert.ok(!out.includes(secret), `${kind}: ${text} -> ${out}`);
    }
    assert.ok(gate.scanText(text).length > 0, `gate missed: ${text}`);
  }
});

test("spaced digit runs after code / pin / safe words, cards and IBANs are redacted and flagged", () => {
  assert.ok(
    !/4 8 1 5 9 2/.test(
      sanitizeText("the code to the safe is 4 8 1 5 9 2", { kind: "note" }),
    ),
  );
  assert.ok(
    !/4242 4242/.test(
      sanitizeText("Stripe test card 4242 4242 4242 4242 exp 12/30", {
        kind: "note",
      }),
    ),
  );
  assert.ok(
    !/0532 0130/.test(
      sanitizeText("IBAN DE89 3704 0044 0532 0130 00", { kind: "note" }),
    ),
  );
  assert.ok(gate.scanText("the code to the safe is 4 8 1 5 9 2").length > 0);
  assert.ok(gate.scanText("card 4242 4242 4242 4242").length > 0);
  assert.equal(
    sanitizeText("Meeting 2026 10 25", { kind: "note" }),
    "Meeting 2026 10 25",
  );
});

test("the gate is script-agnostic: tokens of letters+digits in any script are flagged, plain words are not", () => {
  assert.ok(gate.scanText("x Лето2026Лето2026 y").length > 0);
  assert.ok(gate.scanText("x شمس٢٠٢٦شمس٢٠٢٦ y").length > 0);
  assert.deepEqual(
    gate.scanText("Daily summary of new customers and invoices"),
    [],
  );
  assert.deepEqual(gate.scanText("每日客户摘要报告"), []);
});

test("connection types, node types, env names, cron/schedule strings go through the sanitiser", () => {
  const secret = "Zq8wRt5Yu3Kp9mX2";
  const m = analyzeWorkflow({
    name: "x",
    nodes: [
      { name: "A", type: "n8n-nodes-base.noOp" },
      { name: "B", type: `community-node-password-${secret}` },
      {
        name: "T",
        type: "n8n-nodes-base.scheduleTrigger",
        parameters: {
          rule: {
            interval: [
              {
                field: "cronExpression",
                expression: `0 9 * * * password: ${secret}`,
              },
            ],
          },
        },
      },
      {
        name: "C",
        type: "n8n-nodes-base.code",
        parameters: {
          jsCode: `return $env.TOKEN_${secret} + $vars.pass_${secret};`,
        },
      },
    ],
    connections: {
      A: {
        [`ai_tool_${secret}_x`]: [[{ node: "B", type: "x", index: 0 }]],
        main: [[{ node: "B", type: "main", index: 0 }]],
      },
    },
  });
  assert.ok(!JSON.stringify(m).includes(secret));
});

test("gitleaks status: broken fails closed with exit 3, absent warns and is noted in the header, --no-gitleaks is silent", async () => {
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const gatePath = require.resolve("../src/gate");
  const cliPath = require.resolve("../src/cli");
  const real = require("../src/gate");
  const src = fs.mkdtempSync(path.join(os.tmpdir(), "glsrc-"));
  fs.writeFileSync(
    path.join(src, "a.json"),
    JSON.stringify({
      name: "a",
      nodes: [{ name: "n", type: "n8n-nodes-base.noOp" }],
      connections: {},
    }),
  );
  const run = async (status, extra = []) => {
    const orig = real.gitleaksStatus;
    real.gitleaksStatus = () => status;
    delete require.cache[cliPath];
    const errs = [];
    const out = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), "glout-")),
      "pack",
    );
    try {
      const { main } = require("../src/cli");
      const code = await main(
        ["--from-dir", src, "--out", out, "--date", "2026-01-01", ...extra],
        {},
        { out: () => {}, err: (s) => errs.push(s) },
      );
      return {
        code,
        errs: errs.join("\n"),
        out,
        index: fs.existsSync(path.join(out, "index.md"))
          ? fs.readFileSync(path.join(out, "index.md"), "utf8")
          : "",
      };
    } finally {
      real.gitleaksStatus = orig;
      delete require.cache[cliPath];
      void gatePath;
    }
  };
  let r = await run("broken");
  assert.equal(r.code, 3);
  assert.match(r.errs, /installed but broken/);
  assert.ok(!fs.existsSync(r.out));
  r = await run("absent");
  assert.equal(r.code, 0);
  assert.match(r.errs, /gitleaks was not found/);
  assert.match(
    r.index,
    /independent gitleaks scan: not run \(gitleaks not installed\)/,
  );
  r = await run("absent", ["--no-gitleaks"]);
  assert.equal(r.code, 0);
  assert.ok(!/gitleaks/i.test(r.errs));
  assert.match(r.index, /not run \(--no-gitleaks\)/);
});
