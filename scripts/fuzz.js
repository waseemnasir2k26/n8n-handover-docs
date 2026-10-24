#!/usr/bin/env node
"use strict";
// npm run fuzz. Part 1: plant hostile secrets in every field of ~1000 workflows, generate packs in memory
// and count leaks that reached the output (must be 0). Part 2: inject secrets into the FINISHED files so
// that only the final gate can catch them, and count how many it stops (must be all).
const { generate, scanPack } = require("../src/generate");
const { cases, INJECT } = require("./fuzz-corpus");

async function run(includeNotes) {
  let total = 0;
  let leaksExit0 = 0;
  let gateStops = 0;
  let leaksCaughtByGate = 0;
  const examples = [];
  for (const c of cases()) {
    total++;
    const { files, findings } = await generate([structuredClone(c.wf)], {
      date: "2026-01-01",
      includeNotes,
    });
    const out = Object.values(files).join("\n");
    const leaked = c.tokens.filter((t) => out.includes(t));
    if (findings.length) gateStops++;
    if (leaked.length && findings.length) leaksCaughtByGate++;
    if (leaked.length && !findings.length) {
      leaksExit0++;
      if (examples.length < 10)
        examples.push(`${c.id} (${leaked.length} token(s))`);
    }
  }
  return { total, leaksExit0, gateStops, leaksCaughtByGate, examples };
}

// the scrubber is bypassed on purpose: text appended to the finished index.md, a workflow .md, index.html, inventory.csv
async function injected() {
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
  let total = 0;
  let stopped = 0;
  const missed = [];
  for (const payload of INJECT) {
    for (const file of ["index.md", "ok.md", "index.html", "inventory.csv"]) {
      total++;
      const files = { ...base };
      files[file] +=
        file === "index.html" ? `\n<p>${payload}</p>\n` : `\n${payload}\n`;
      if (scanPack(files).some((f) => f.file === file)) stopped++;
      else missed.push(`${file}: ${payload.slice(0, 24)}`);
    }
  }
  return { total, stopped, missed };
}

(async () => {
  let bad = 0;
  for (const includeNotes of [false, true]) {
    const r = await run(includeNotes);
    console.log(
      `${includeNotes ? "with --include-notes" : "default (notes hidden)"}: ${r.total} cases, leaks with exit 0: ${r.leaksExit0}, stopped by the final gate (exit 3): ${r.gateStops}, of which real leaks the gate caught: ${r.leaksCaughtByGate}`,
    );
    if (r.examples.length)
      console.log("  leaking cases:", r.examples.join("; "));
    bad += r.leaksExit0;
  }
  const inj = await injected();
  console.log(
    `injected after rendering (scrubber bypassed): ${inj.total} cases, stopped by the final gate (exit 3): ${inj.stopped}`,
  );
  if (inj.missed.length) {
    console.log("  gate missed:", inj.missed.slice(0, 10).join("; "));
    bad += inj.missed.length;
  }
  console.log(
    bad === 0
      ? "FUZZ PASSED: 0 leaks with exit 0, every injected case stopped by the gate"
      : `FUZZ FAILED: ${bad} problem(s)`,
  );
  process.exitCode = bad === 0 ? 0 : 1;
})();
