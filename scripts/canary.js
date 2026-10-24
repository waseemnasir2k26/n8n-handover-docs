#!/usr/bin/env node
"use strict";
// Canary demo: build a hostile workflow full of fake secrets, generate the pack,
// show that nothing leaks, then simulate a scrubber bug and show the final scan
// catching it. No network, no files written.
const { generate, scanPack } = require("../src/generate");

const canaries = {
  "sticky note password": "hunter" + "2hunter2",
  "sticky note apikey=": "zzzz" + "1234567890",
  'sticky note "pw is"': "Winter" + "2026!!",
  "node name api_key=": "NAMELEAK" + "123456789",
  "tag token:": "tgTok9" + "Zq7Lm2",
  "Code node yaml secret:": "yamlSecret" + "77Ab",
  "Code node PASSWORD=": "Passw0rd" + "Canary9",
  "Authorization: Token": "AuthTokCanary" + "8842xx",
  "high-entropy blob": "Qw3rTy" + "Ui0pAs" + "Df7gHj" + "Kl9zXc",
};

const wf = {
  id: "canary-workflow-id",
  name: "Canary workflow",
  tags: [{ name: `token: ${canaries["tag token:"]}` }],
  nodes: [
    {
      name: `Call api_key=${canaries["node name api_key="]}`,
      type: "n8n-nodes-base.noOp",
      parameters: {},
    },
    {
      name: "Note",
      type: "n8n-nodes-base.stickyNote",
      parameters: {
        content: `password: ${canaries["sticky note password"]} apikey=${canaries["sticky note apikey="]}\npw is ${canaries['sticky note "pw is"']}\nblob ${canaries["high-entropy blob"]}`,
      },
    },
    {
      name: "Code",
      type: "n8n-nodes-base.code",
      parameters: {
        jsCode: `PASSWORD=${canaries["Code node PASSWORD="]}\nsecret: ${canaries["Code node yaml secret:"]}\nAuthorization: Token ${canaries["Authorization: Token"]}`,
      },
    },
  ],
  connections: {},
};

(async () => {
  const { files, findings } = await generate([wf], { date: "2026-01-01" });
  const all = Object.values(files).join("\n");
  console.log(
    `Step 1: generated ${Object.keys(files).length} files from a workflow with ${Object.keys(canaries).length} planted secrets`,
  );
  let leaked = 0;
  for (const [label, v] of Object.entries(canaries)) {
    const hit = all.includes(v);
    if (hit) leaked++;
    console.log(`  ${hit ? "LEAKED " : "removed"}  ${label}`);
  }
  console.log(`  final scan findings on the clean pack: ${findings.length}`);

  console.log(
    "\nStep 2: simulate a scrubber bug by pasting secrets into the finished files, then run the final scan",
  );
  const bad = { ...files };
  bad["index.md"] += `\npassword: ${canaries["sticky note password"]}\n`;
  bad["index.html"] +=
    `\n<p>Authorization: Token ${canaries["Authorization: Token"]}</p>\n`;
  bad["inventory.csv"] +=
    `"x","","","","","blob ${canaries["high-entropy blob"]}"\r\n`;
  const found = scanPack(bad);
  for (const f of found)
    console.log(`  ${f.file}:${f.line}  ${f.kind}  [value masked]`);
  console.log(
    `  the CLI would stop here with exit code 3 and write nothing (override: --allow-findings)`,
  );

  const ok = leaked === 0 && findings.length === 0 && found.length >= 3;
  console.log(ok ? "\nCanary check PASSED" : "\nCanary check FAILED");
  process.exitCode = ok ? 0 : 1;
})();
