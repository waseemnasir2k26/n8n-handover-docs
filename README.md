# n8n-handover-docs: a client handover pack from your n8n workflows, without the 2-hour call

![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Node 20+](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)
![Dependencies: 0](https://img.shields.io/badge/dependencies-0-blue.svg)

**You built 15 automations. The client's next developer opens n8n and sees 15 boxes with no explanation. This writes the explanation.**

Point it at exported workflow JSON (or your live n8n API, read-only) and it produces, per workflow and as an index:

- what it does in plain English, what triggers it, and the schedule (cron expressions are translated)
- a step list and a Mermaid flowchart, with IF / Switch branches and AI agent model/tool/memory links labelled
- external services touched, credential **names and types** only, env vars and `$vars` referenced
- webhooks (method + path), error handling present or missing, rate limits and caps, sub-workflow calls
- warnings: pinned data, hard-coded secrets (location only, value masked), webhooks with no auth
- a "When it breaks" runbook per service (auth expired, 429, schema change) with the node names to look at
- `inventory.csv`: workflow x service x credential, safe to open in Excel

Zero dependencies. Node 20+.

![Sample pack](docs/sample-pack.png)

Browse a real generated sample: [examples/sample-pack/](examples/sample-pack/) (open `index.html`, or read the `.md` files on GitHub where the diagrams render).

## 60-second quickstart

From exported JSON (n8n: workflow menu > Download):

```bash
git clone https://github.com/waseemnasir2k26/n8n-handover-docs.git
cd n8n-handover-docs
node bin/n8n-handover-docs.js --from-dir path/to/exports --out handover --title "Client name"
```

From a live n8n (public API, GET only):

```bash
export N8N_BASE_URL=https://n8n.example.com
export N8N_API_KEY=...            # Settings > n8n API. Read from env only, never written anywhere
node bin/n8n-handover-docs.js --live --tag client-x --active-only --out handover
```

Try it without any n8n: `npm run demo` (builds `examples/sample-pack` from `examples/workflows`).

Output folder:

| File                        | What it is                                                                                                                                                                          |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `index.html`                | One self-contained page: overview, credential list to transfer, env vars to set, every workflow in full. Has print CSS: open it and use "Print / save as PDF" to get `handover.pdf` |
| `index.md`, `<workflow>.md` | The same content as GitHub-friendly Markdown with `mermaid` blocks                                                                                                                  |
| `inventory.csv`             | Workflows x services x credentials. Formula-injection safe                                                                                                                          |

## Options

| Flag                  | Meaning                                                                                                |
| --------------------- | ------------------------------------------------------------------------------------------------------ |
| `--from-dir <folder>` | Folder of exported `.json` (single workflow, array, or `{data:[...]}` API shape; searched recursively) |
| `--live`              | Read from the n8n public API. `--tag`, `--active-only`, `--limit` narrow it                            |
| `--out <folder>`      | Default `./handover`                                                                                   |
| `--title <text>`      | Pack title, e.g. the client name                                                                       |
| `--show-hosts`        | Show real webhook URLs and HTTP hostnames. Default is hidden                                           |
| `--offline`           | No CDN script in `index.html`; diagrams stay as Mermaid text                                           |
| `--llm`               | Add a plain-English AI summary per workflow (see below)                                                |
| `--date YYYY-MM-DD`   | Date printed in the pack (for reproducible output)                                                     |

The HTML loads Mermaid 11.4.1 from jsDelivr with a pinned version and an SRI hash. If it cannot load, the diagram source stays visible as text.

## What is never included

- Credential values, credential IDs, workflow IDs, or your API key. Output is checked against every ID and the key found in the input, and any hit is stripped.
- Parameter values. Hard-coded secrets are reported by node and field only, as `[masked, N chars]`.
- Pinned (frozen) test data contents. Only the fact that it exists.
- Hostnames, unless you pass `--show-hosts`. URLs inside sticky notes and node names are replaced with `<url hidden>` by default.

Review the pack before you send it. Node names, credential names and sticky notes are copied as written (with secret patterns and URLs scrubbed), and a person's judgement is still the last gate.

## Live mode safety

GET requests only, to `/api/v1/workflows`. The key goes in one `X-N8N-API-KEY` header, never in a URL, never logged, and is scrubbed from every error message. Redirects are not followed (`redirect: manual`), so a misconfigured URL cannot forward your key to another host. `http://` is accepted only for localhost.

## Optional AI summary

`--llm` adds a short summary per workflow, labelled "unverified". It uses a free option, first match wins: `HANDOVER_OLLAMA_MODEL` (local Ollama, `OLLAMA_HOST` optional), `GROQ_API_KEY`, or `GEMINI_API_KEY`. The model receives only node names, node types and connections: no parameters, credentials, URLs or pinned data. If the call fails, the pack is built without it.

## "When it breaks" runbook

Generated from node types by a fixed rule table in [src/rules.js](src/rules.js) (Google and Microsoft OAuth, LLM providers, databases, chat, email, CMS, generic HTTP, plus webhook, schedule, Code, sub-workflow and AI agent notes). It lists likely failures and the node names to open. It does not know your systems; treat it as a starting checklist.

## Limits

- It reads workflow structure, not run history. It cannot tell you whether a workflow actually works today.
- Plain-English text is rule-based. Expect "Edit Fields (Set), sets 3 field(s)", not business meaning. Sticky notes are copied in, so write good ones.
- Unknown or community nodes get a generic entry: the service name is guessed from the credential type.
- Cron reading covers common shapes; unusual expressions are shown raw.
- Secret detection is pattern-based (common key formats, `api_key=`-style assignments, sensitive header names). It will miss some secrets and may flag a few harmless strings.
- Very large workflows produce large diagrams; Mermaid limits are raised but readability drops past roughly 100 nodes.
- Tested against synthetic fixtures covering n8n 1.x and 2.x workflow shapes and against a live instance with about 100 workflows. n8n changes node schemas often; open an issue with a redacted export if something breaks.

## For you if

- You are a freelancer or agency handing automations to a client and want the docs to exist before the call.
- You inherit someone else's n8n and want a map and a credential checklist first.
- You need an inventory of what talks to what before you rotate keys or migrate hosts.

## Develop

```bash
npm test       # node --test, no dependencies
npm run demo
```

MIT licensed, no telemetry.

---

**Need this wired into your business? SkynetLabs builds voice agents, n8n back offices and sites that convert → https://skynetjoe.com**
