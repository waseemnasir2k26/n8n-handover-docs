#!/usr/bin/env node
"use strict";
// npm run fuzz: plant hostile secrets in every field of ~900 workflows, generate packs in memory and count
// (a) leaks that reached the output, (b) cases the final gate stopped (exit 3 in the CLI).
const { generate } = require("../src/generate");
const { cases } = require("./fuzz-corpus");

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
  console.log(
    bad === 0
      ? "FUZZ PASSED: 0 leaks with exit 0"
      : `FUZZ FAILED: ${bad} leaks with exit 0`,
  );
  process.exitCode = bad === 0 ? 0 : 1;
})();
