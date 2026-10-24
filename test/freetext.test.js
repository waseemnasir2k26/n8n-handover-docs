"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { generate, scanPack } = require("../src/generate");
const {
  scrubText,
  scanText,
  findSecrets,
  redactContacts,
  tokenLike,
} = require("../src/secrets");
const { analyzeWorkflow } = require("../src/parse");
const { mdEsc } = require("../src/util");

// Canary values assembled at runtime so no secret-looking literal sits in the repo.
const C = {
  pw1: "hunter" + "2hunter2",
  key1: "zzzz" + "1234567890",
  pw2: "Winter" + "2026!!",
  nameKey: "NAMELEAK" + "123456789",
  tagTok: "tg" + "Tok9" + "Zq7Lm2",
  yaml: "yamlSecret" + "77Ab",
  envPw: "Passw0rd" + "Canary9",
  authTok: "AuthTokCanary" + "8842xx",
  credName: "CredNm" + "Secret55x",
  entropy: "Qw3rTy" + "Ui0pAs" + "Df7gHj" + "Kl9zXc",
  hex: "a1b2c3d4".repeat(5),
  email: "jane.doe" + "@example.test",
  phone: "+62 812 3456 7890",
  wh: "customer-intake-endpoint",
};

function canaryWorkflow() {
  return {
    id: "id-canary-0001",
    name: "Canary flow",
    tags: [{ name: `token: ${C.tagTok}` }],
    nodes: [
      {
        name: "Hook",
        type: "n8n-nodes-base.webhook",
        webhookId: "w",
        parameters: { path: C.wh, httpMethod: "POST" },
      },
      {
        name: `Call api_key=${C.nameKey}`,
        type: "n8n-nodes-base.noOp",
        parameters: {},
      },
      {
        name: "Note A",
        type: "n8n-nodes-base.stickyNote",
        parameters: {
          content: `password: ${C.pw1} apikey=${C.key1}\npw is ${C.pw2}\nAuthorization: Token ${C.authTok}\nmail ${C.email} call ${C.phone}\nblob ${C.entropy} and ${C.hex}`,
        },
      },
      {
        name: "Code",
        type: "n8n-nodes-base.code",
        parameters: {
          jsCode: `PASSWORD=${C.envPw}\nsecret: ${C.yaml}\nconst h = 'Authorization: Token ${C.authTok}';`,
        },
        credentials: {
          someApi: { id: "cred-canary-zzzz", name: `secret is ${C.credName}` },
        },
      },
    ],
    connections: {
      Hook: {
        main: [[{ node: `Call api_key=${C.nameKey}`, type: "main", index: 0 }]],
      },
    },
  };
}

const VALUES = [
  C.pw1,
  C.key1,
  C.pw2,
  C.nameKey,
  C.tagTok,
  C.yaml,
  C.envPw,
  C.authTok,
  C.credName,
  C.entropy,
  C.hex,
  C.wh,
];

test("canary: no secret value survives in ANY output format (md, html, csv, index)", async () => {
  const { files, findings } = await generate([canaryWorkflow()], {
    date: "2026-01-01",
  });
  const all = Object.values(files).join("\n");
  for (const v of VALUES)
    assert.ok(!all.includes(v), `leaked ${v.slice(0, 5)}...`);
  for (const [name, content] of Object.entries(files)) {
    for (const v of VALUES)
      assert.ok(!content.includes(v), `${name} leaked ${v.slice(0, 5)}...`);
  }
  assert.deepEqual(findings, []);
  assert.ok(
    Object.keys(files).includes("inventory.csv") &&
      Object.keys(files).includes("index.html"),
  );
});

test("quoted vs unquoted vs prose forms are all scrubbed", () => {
  const v = "Ab9" + "xK2mQ7";
  const forms = [
    `password: ${v}`,
    `password:${v}`,
    `password = ${v}`,
    `password="${v}"`,
    `"password": "${v}"`,
    `pw is ${v}`,
    `pwd - ${v}`,
    `api_key=${v}`,
    `API-KEY: ${v}`,
    `client_secret: ${v}`,
    `access_key=${v}`,
    `private_key is ${v}`,
    `secret: ${v}`,
    `Authorization: Bearer ${v}${v}`,
    `Authorization: Token ${v}`,
    `x token=${v}`,
  ];
  for (const f of forms) {
    const out = scrubText(f);
    assert.ok(
      !out.includes(v),
      `not scrubbed: ${f.replace(v, "***")} -> ${out.replace(v, "***")}`,
    );
    assert.ok(scanText(f).length > 0, `scanner missed: ${f.replace(v, "***")}`);
  }
});

test("prose that merely mentions the words is left alone", () => {
  for (const t of [
    "Check Slack token: Code",
    "password is required",
    "Refresh token - used daily",
    "secret-host",
    "Token expired, key rotated",
    "googleSheetsOAuth2Api",
  ]) {
    assert.equal(scrubText(t), t);
    assert.deepEqual(scanText(t), [], t);
  }
});

test("entropy: long mixed tokens redacted, ordinary long words and slugs are not", () => {
  assert.ok(tokenLike(C.entropy));
  assert.ok(tokenLike(C.hex));
  assert.ok(!tokenLike("Process-all-customer-invoices-weekly"));
  assert.ok(!tokenLike("googleSheetsOAuth2Api"));
  assert.ok(!tokenLike("lg-04-maps-harvest-and-more"));
  assert.equal(scrubText(`x ${C.entropy} y`), "x [REDACTED] y");
});

test("findSecrets catches unquoted PASSWORD=, yaml secret:, Authorization: Token (location only)", () => {
  const f = findSecrets("Code", {
    jsCode: `PASSWORD=${C.envPw}\nsecret: ${C.yaml}\nAuthorization: Token ${C.authTok}`,
  });
  assert.ok(f.length >= 3, JSON.stringify(f));
  const json = JSON.stringify(f);
  for (const v of [C.envPw, C.yaml, C.authTok]) assert.ok(!json.includes(v));
  assert.deepEqual(
    findSecrets("c", {
      jsCode:
        "const token = getToken(user);\nconst password = process.env.PW_VAR;",
    }),
    [],
  );
});

test("webhook paths are masked by default; full only with showWebhookPaths", () => {
  const wf = canaryWorkflow();
  const hidden = analyzeWorkflow(wf);
  assert.equal(hidden.webhooks[0].path, C.wh.slice(0, 4) + "…");
  assert.ok(!hidden.webhooks[0].url.includes(C.wh));
  const shown = analyzeWorkflow(
    { ...wf, nodes: wf.nodes },
    { showWebhookPaths: true },
  );
  assert.ok(shown.webhooks[0].path.length > 8);
  const short = analyzeWorkflow({
    nodes: [
      {
        name: "h",
        type: "n8n-nodes-base.webhook",
        parameters: { path: "chat" },
      },
    ],
  });
  assert.equal(short.webhooks[0].path, "chat");
});

test("contacts in sticky notes hidden by default; names/tags only with --redact-contacts; --keep-contacts opts out", () => {
  const wf = canaryWorkflow();
  wf.name = `Flow for ${C.email}`;
  const defModel = analyzeWorkflow(wf);
  const def = JSON.stringify(defModel);
  const notes = defModel.notes.join(" ");
  assert.ok(
    !notes.includes(C.phone) && !notes.includes("jane.doe"),
    "note contacts hidden",
  );
  assert.ok(
    def.includes(C.email),
    "workflow name keeps e-mail without --redact-contacts",
  );
  const all = JSON.stringify(analyzeWorkflow(wf, { redactContacts: true }));
  assert.ok(!all.includes(C.email));
  const keep = JSON.stringify(analyzeWorkflow(wf, { keepContacts: true }));
  assert.ok(keep.includes(C.phone));
  assert.equal(
    redactContacts("on 2026-10-25 call 12345"),
    "on 2026-10-25 call 12345",
  );
});

test("final scan catches an injected leak in every format and reports file:line without values", async () => {
  const { files } = await generate([canaryWorkflow()], { date: "2026-01-01" });
  assert.deepEqual(scanPack(files), []);
  const bad = { ...files };
  bad["index.md"] += `\npassword: ${C.pw1}\n`;
  bad["index.html"] += `\n<p>api_key=${C.key1}</p>\n`;
  bad["inventory.csv"] += `"x","","","","","pw is ${C.pw2}"\r\n`;
  const found = scanPack(bad);
  assert.deepEqual([...new Set(found.map((f) => f.file))].sort(), [
    "index.html",
    "index.md",
    "inventory.csv",
  ]);
  const json = JSON.stringify(found);
  for (const v of [C.pw1, C.key1, C.pw2]) assert.ok(!json.includes(v));
  assert.ok(found.every((f) => Number.isInteger(f.line) && f.kind));
});

test("CLI exits 3 and writes nothing when the final scan finds something; --allow-findings overrides", async () => {
  const gen = require("../src/generate");
  const cliPath = require.resolve("../src/cli");
  const orig = gen.generate;
  gen.generate = async () => ({
    files: { "index.md": `password: ${C.pw1}\n` },
    items: [],
    warnings: [],
    findings: [
      { file: "index.md", line: 1, kind: 'unquoted assignment to "password"' },
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
      JSON.stringify(canaryWorkflow()),
    );
    const errs = [];
    const io = { out: () => {}, err: (s) => errs.push(s) };
    assert.equal(await main(["--from-dir", src, "--out", out], {}, io), 3);
    assert.ok(!fs.existsSync(out));
    assert.match(errs.join("\n"), /index\.md:1/);
    assert.ok(!errs.join("\n").includes(C.pw1));
    assert.equal(
      await main(["--from-dir", src, "--out", out, "--allow-findings"], {}, io),
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

test("javascript:/data: schemes are neutralised in markdown text", async () => {
  assert.ok(!/javascript:/i.test(mdEsc("click javascript:alert(1) now")));
  assert.ok(!/data\s*:/i.test(mdEsc("data:text/html;base64,PHNjcmlwdD4=")));
  const wf = {
    name: "[x](javascript:alert(1)) <javascript:alert(2)>",
    nodes: [],
    connections: {},
  };
  const { files } = await generate([wf], { date: "2026-01-01" });
  for (const [n, c] of Object.entries(files))
    if (n.endsWith(".md"))
      assert.ok(!/\]\(javascript:|<javascript:/i.test(c), n);
});

test("--diagram-fallback / --offline show the reason", async () => {
  const a = (
    await generate([canaryWorkflow()], {
      date: "2026-01-01",
      diagramFallback: true,
    })
  ).files["index.html"];
  assert.match(a, /Diagram shown as text: --diagram-fallback was used/);
  assert.ok(!/<script/.test(a));
});
