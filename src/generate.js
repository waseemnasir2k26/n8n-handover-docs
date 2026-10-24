"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { analyzeWorkflow } = require("./parse");
const { workflowBlocks, indexBlocks } = require("./doc");
const { blocksToMd, htmlPage, inventoryCsv } = require("./render");
const { slugify } = require("./util");
const { summarize } = require("./llm");

function unwrap(j) {
  if (Array.isArray(j)) return j.flatMap(unwrap);
  if (j && typeof j === "object") {
    if (Array.isArray(j.nodes)) return [j];
    if (Array.isArray(j.data)) return j.data.flatMap(unwrap);
    if (j.workflow && Array.isArray(j.workflow.nodes)) return [j.workflow];
  }
  return [];
}

function loadDir(dir, warn = () => {}) {
  const found = [];
  const walk = (d, depth) => {
    if (depth > 4) return;
    for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
      if (ent.name === "node_modules" || ent.name.startsWith(".")) continue;
      const p = path.join(d, ent.name);
      if (ent.isDirectory()) walk(p, depth + 1);
      else if (ent.isFile() && /\.json$/i.test(ent.name)) found.push(p);
    }
  };
  walk(dir, 0);
  found.sort();
  const out = [];
  for (const f of found) {
    try {
      if (fs.statSync(f).size > 25 * 1024 * 1024) {
        warn(`skipped ${path.basename(f)}: file over 25 MB`);
        continue;
      }
      const wfs = unwrap(JSON.parse(fs.readFileSync(f, "utf8")));
      if (!wfs.length) {
        warn(`skipped ${path.basename(f)}: not an n8n workflow export`);
        continue;
      }
      out.push(...wfs);
    } catch {
      warn(`skipped ${path.basename(f)}: not valid JSON`);
    }
  }
  return out;
}

function forbiddenStrings(workflows, extra = []) {
  const set = new Set(extra.filter((s) => s && s.length >= 6));
  for (const wf of workflows) {
    if (wf && typeof wf.id === "string" && wf.id.length >= 6) set.add(wf.id);
    for (const n of Array.isArray(wf && wf.nodes) ? wf.nodes : []) {
      const creds =
        n && n.credentials && typeof n.credentials === "object"
          ? n.credentials
          : {};
      for (const c of Object.values(creds))
        if (c && typeof c.id === "string" && c.id.length >= 6) set.add(c.id);
    }
  }
  return [...set];
}

/**
 * Pure pipeline: workflows[] -> { files: {relativePath: string}, items, warnings }
 */
async function generate(workflows, opts = {}) {
  const warnings = [];
  const idToName = new Map();
  for (const wf of workflows)
    if (wf && typeof wf.id === "string" && typeof wf.name === "string")
      idToName.set(wf.id, wf.name);
  const taken = new Set();
  const items = workflows.map((wf) => {
    const m = analyzeWorkflow(wf, {
      idToName,
      showHosts: !!opts.showHosts,
      baseUrl: opts.baseUrl,
    });
    return { m, slug: slugify(m.name, taken) };
  });
  const slugByName = new Map(items.map(({ m, slug }) => [m.name, slug]));
  const date = opts.date || new Date().toISOString().slice(0, 10);
  const title = opts.title || "n8n handover pack";

  const files = {};
  const sections = [];
  for (const { m, slug } of items) {
    let llm = null;
    if (opts.llm)
      llm = await summarize(
        m,
        opts.env || process.env,
        opts.fetchImpl || globalThis.fetch,
        (w) => warnings.push(w),
      );
    const blocks = workflowBlocks(m, { anchor: `wf-${slug}`, slugByName, llm });
    sections.push({ slug, blocks });
    files[`${slug}.md`] = "[Back to index](index.md)\n\n" + blocksToMd(blocks);
  }
  const idx = indexBlocks(items, { title, date });
  files["index.md"] = blocksToMd(idx);
  files["index.html"] = htmlPage({
    title,
    indexBlocks: idx,
    sections,
    offline: !!opts.offline,
  });
  files["inventory.csv"] = inventoryCsv(items);

  // Backstop: no credential id / workflow id / API key may appear in any output.
  const forbidden = forbiddenStrings(workflows, [opts.apiKey]);
  let leaks = 0;
  for (const k of Object.keys(files)) {
    for (const f of forbidden) {
      if (files[k].includes(f)) {
        leaks++;
        files[k] = files[k].split(f).join("[redacted]");
      }
    }
  }
  if (leaks)
    warnings.push(
      `removed ${leaks} accidental occurrence(s) of an id or key from the output`,
    );
  return { files, items, warnings };
}

function writeFiles(outDir, files) {
  fs.mkdirSync(outDir, { recursive: true });
  for (const [rel, content] of Object.entries(files)) {
    if (rel.includes("/") || rel.includes("\\") || rel.includes(".."))
      throw new Error("refusing to write outside the output folder");
    fs.writeFileSync(path.join(outDir, rel), content, "utf8");
  }
}

module.exports = { generate, loadDir, writeFiles, unwrap, forbiddenStrings };
