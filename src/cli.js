"use strict";
const path = require("node:path");
const { parseArgs } = require("node:util");
const { generate, loadDir, writeFiles } = require("./generate");
const { fetchWorkflows, normaliseBase, scrubKey } = require("./api");

const HELP = `n8n-handover-docs: generate a client handover pack from n8n workflows

Usage:
  n8n-handover-docs --from-dir <folder> [options]
  n8n-handover-docs --live [--tag <name>] [options]

Input:
  --from-dir <folder>   folder of exported workflow .json files (searched recursively)
  --live                read from the n8n public API (GET only).
                        Env: N8N_BASE_URL, N8N_API_KEY (the key is never logged or written)
  --tag <name>          with --live: only workflows with this tag
  --active-only         with --live: only active workflows
  --limit <n>           with --live: at most n workflows

Output:
  --out <folder>        default ./handover  (index.html, index.md, <workflow>.md, inventory.csv)
  --title <text>        title of the pack (e.g. the client name)
  --show-hosts          show real hostnames (webhook URLs, HTTP endpoints). Default: hidden
  --offline             no CDN script in index.html; Mermaid diagrams stay as text
  --llm                 add a plain-English AI summary per workflow. Needs HANDOVER_OLLAMA_MODEL,
                        or GROQ_API_KEY, or GEMINI_API_KEY. Only names, types and connections are sent.
  --date <YYYY-MM-DD>   date printed in the pack (default: today)
  -h, --help
`;

async function main(argv, env = process.env, io = {}) {
  const out = io.out || ((s) => process.stdout.write(s + "\n"));
  const err = io.err || ((s) => process.stderr.write(s + "\n"));
  let args;
  try {
    args = parseArgs({
      args: argv,
      options: {
        "from-dir": { type: "string" },
        live: { type: "boolean" },
        tag: { type: "string" },
        "active-only": { type: "boolean" },
        limit: { type: "string" },
        out: { type: "string" },
        title: { type: "string" },
        "show-hosts": { type: "boolean" },
        offline: { type: "boolean" },
        llm: { type: "boolean" },
        date: { type: "string" },
        help: { type: "boolean", short: "h" },
      },
      allowPositionals: false,
    }).values;
  } catch (e) {
    err(`${e.message}\n\n${HELP}`);
    return 2;
  }
  if (args.help) {
    out(HELP);
    return 0;
  }
  if (!!args["from-dir"] === !!args.live) {
    err(`Choose exactly one of --from-dir or --live.\n\n${HELP}`);
    return 2;
  }
  if (args.date && !/^\d{4}-\d{2}-\d{2}$/.test(args.date)) {
    err("--date must look like 2026-01-31");
    return 2;
  }
  const limit = args.limit ? Number.parseInt(args.limit, 10) : 0;
  if (args.limit && !(limit > 0)) {
    err("--limit must be a positive number");
    return 2;
  }

  const { N8N_API_KEY: rawKey } = env;
  const apiKey = typeof rawKey === "string" ? rawKey : "";
  let workflows;
  let baseUrl = null;
  try {
    if (args.live) {
      if (!env.N8N_BASE_URL) throw new Error("N8N_BASE_URL is not set");
      baseUrl = normaliseBase(env.N8N_BASE_URL);
      workflows = await fetchWorkflows({
        baseUrl,
        apiKey,
        tag: args.tag,
        activeOnly: args["active-only"],
        limit,
        fetchImpl: io.fetchImpl || globalThis.fetch,
      });
      if (args.tag) {
        const t = args.tag.toLowerCase();
        workflows = workflows.filter(
          (w) =>
            !Array.isArray(w.tags) ||
            w.tags.some((x) => String((x && x.name) || x).toLowerCase() === t),
        );
      }
    } else {
      workflows = loadDir(path.resolve(args["from-dir"]), (w) =>
        err(`warning: ${w}`),
      );
      if (limit) workflows = workflows.slice(0, limit);
    }
  } catch (e) {
    err(`error: ${scrubKey(e.message, apiKey)}`);
    return 1;
  }
  if (!workflows.length) {
    err("No workflows found. Nothing written.");
    return 1;
  }

  let result;
  try {
    result = await generate(workflows, {
      showHosts: !!args["show-hosts"],
      baseUrl,
      offline: !!args.offline,
      llm: !!args.llm,
      title: args.title,
      date: args.date,
      env,
      apiKey,
      fetchImpl: io.fetchImpl || globalThis.fetch,
    });
  } catch (e) {
    err(`error: could not build the pack: ${scrubKey(e && e.message, apiKey)}`);
    return 1;
  }
  const outDir = path.resolve(args.out || "handover");
  writeFiles(outDir, result.files);
  result.warnings.forEach((w) => err(`warning: ${scrubKey(w, apiKey)}`));
  const nWarn = result.items.reduce((n, { m }) => n + m.warnings.length, 0);
  out(
    `Wrote ${Object.keys(result.files).length} files for ${result.items.length} workflow(s) to ${outDir}`,
  );
  out(
    `${nWarn} warning(s) to review before handover (see "Needs attention" in index.html).`,
  );
  return 0;
}

module.exports = { main, HELP };
