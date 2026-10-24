"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { generate } = require("../src/generate");
const { cases } = require("../scripts/fuzz-corpus");

// The adversarial corpus (homoglyphs, zero-width, fullwidth, markdown/table/entity wrappers, newline between
// key and value, natural language, URL-encoded, base64, split keys, ...) planted in every field that can
// reach the pack. Rule: a leaked token is only acceptable if the final gate stopped the run (CLI exit 3).
async function sweep(includeNotes) {
  let total = 0;
  const leaks = [];
  const stops = [];
  for (const c of cases()) {
    total++;
    const { files, findings } = await generate([structuredClone(c.wf)], {
      date: "2026-01-01",
      includeNotes,
    });
    const out = Object.values(files).join("\n");
    const leaked = c.tokens.filter((t) => out.includes(t));
    if (findings.length) stops.push(c.id);
    if (leaked.length && !findings.length)
      leaks.push(`${c.id}: ${leaked.length} token(s)`);
  }
  return { total, leaks, stops };
}

test("fuzz corpus has 375+ cases", () => {
  let n = 0;
  for (const c of cases()) {
    n++;
    void c;
  }
  assert.ok(n >= 375, `only ${n} cases`);
});

test("fuzz: 0 leaks with exit 0 (notes hidden by default)", async () => {
  const r = await sweep(false);
  assert.deepEqual(r.leaks, []);
  assert.ok(r.total >= 375);
});

test("fuzz: 0 leaks with exit 0 (--include-notes)", async () => {
  const r = await sweep(true);
  assert.deepEqual(r.leaks, []);
});

test("fuzz: the scrubber alone handles the corpus, so the gate stops nothing on legitimate-looking runs", async () => {
  const r = await sweep(false);
  assert.deepEqual(r.stops, []);
});
