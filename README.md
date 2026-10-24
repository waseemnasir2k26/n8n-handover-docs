# n8n-handover-docs: a client handover pack from your n8n workflows, without the 2-hour call

![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Node 20+](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)
![Dependencies: 0](https://img.shields.io/badge/dependencies-0-blue.svg)

![A generated workflow page: plain-English summary and the rendered Mermaid flowchart of an AI agent with model, memory and tools](docs/sample-pack.png)

**You built 15 automations. The client's next developer opens n8n and sees 15 boxes with no explanation. This writes the explanation.**

Point it at exported workflow JSON (or your live n8n API, read-only) and it produces, per workflow and as an index:

- what it does in plain English, what triggers it, and the schedule (cron expressions are translated)
- a step list and a Mermaid flowchart, with IF / Switch branches and AI agent model/tool/memory links labelled
- external services touched, credential **names and types** only, env vars and `$vars` referenced
- webhooks (method + shortened path), error handling present or missing, rate limits and caps, sub-workflow calls
- warnings: pinned data, hard-coded secrets (location only, value masked), webhooks with no auth
- a "When it breaks" runbook per service (auth expired, 429, schema change) with the node names to look at
- `inventory.csv`: workflow x service x credential, safe to open in Excel

Zero dependencies. Node 20+. A full generated sample is in [examples/sample-pack/](examples/sample-pack/) (open `index.html`, or read the `.md` files on GitHub where the diagrams render).

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

| File                        | What it is                                                                                                                                                         |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `index.html`                | One self-contained page: overview, credential list to transfer, env vars to set, every workflow in full. Print CSS included: open it and use "Print / save as PDF" |
| `index.md`, `<workflow>.md` | The same content as GitHub-friendly Markdown with `mermaid` blocks                                                                                                 |
| `inventory.csv`             | Workflows x services x credentials. Formula-injection safe                                                                                                         |

## Options

| Flag                               | Meaning                                                                                                |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `--from-dir <folder>`              | Folder of exported `.json` (single workflow, array, or `{data:[...]}` API shape; searched recursively) |
| `--live`                           | Read from the n8n public API. `--tag`, `--active-only`, `--limit` narrow it                            |
| `--out <folder>`                   | Default `./handover`                                                                                   |
| `--title <text>`                   | Pack title, e.g. the client name                                                                       |
| `--show-hosts`                     | Show real webhook URLs and HTTP hostnames (default: hidden)                                            |
| `--show-webhook-paths`             | Show full webhook paths (default: first 4 characters, because a path works like a password)            |
| `--redact-contacts`                | Also hide e-mails and phone numbers in workflow names, tags and credential names                       |
| `--keep-contacts`                  | Do not hide e-mails and phone numbers in sticky notes (default: hidden)                                |
| `--allow-findings`                 | Write the pack even if the final secret scan finds something (see below)                               |
| `--diagram-fallback` / `--offline` | Diagrams as text with the reason shown, no script in the HTML                                          |
| `--llm`                            | Add a plain-English AI summary per workflow (see below)                                                |
| `--date YYYY-MM-DD`                | Date printed in the pack (reproducible output)                                                         |

The HTML loads Mermaid 11.4.1 from jsDelivr with a pinned version and an SRI hash. If it cannot load, the diagram source stays visible as text.

## What is scrubbed, what is checked, what is not

**Never written:** credential values, credential IDs, your API key, parameter values, pinned test data contents. Credentials appear as name and type only.

**Scrubbed while building** (node names, workflow names, tags, credential names, sticky notes, webhook paths, AI summaries):

- known key formats (OpenAI-style, GitHub, Slack, AWS, Google, Stripe, JWT, Bearer/Basic, private keys, credentials in URLs)
- assignments in any form: `password: x`, `api_key=x`, `pw is x`, `secret - x`, quoted or unquoted, plus `Authorization: Token x`
- long mixed-character tokens (20+ characters, upper and lower case, several digits) and 32+ character hex strings
- URLs (hosts hidden unless `--show-hosts`), and e-mails and phone numbers in sticky notes
- webhook paths, shortened to 4 characters unless `--show-webhook-paths`

**Hard-coded secrets in node parameters** (headers, Code nodes, JSON bodies, YAML/.env-style lines) are not copied at all. They are listed by node and field as `[masked, N chars]`.

**Checked after rendering:** the finished text of every output file (`index.html`, `index.md`, each workflow `.md`, `inventory.csv`) is scanned with the full secret detector, and every credential ID, workflow ID and API key found in the input is searched for. Any ID or key hit is stripped. Any secret-pattern hit stops the run: **exit code 3, nothing written**, with `file:line` and the kind of finding (never the value). `--allow-findings` writes the pack anyway.

**Not guaranteed:**

- Plain words used as passwords with no marker in front of them, short secrets without a keyword, and anything in a language or format the patterns do not know.
- Personal data that is not an e-mail or phone number (names, addresses, customer details typed into a node name or note).
- Node names, credential names, workflow names and note text are copied as written after scrubbing. They can still say things you would not send to a third party.
- Pinned data is reported as present, never read out, but check the source export before sharing it.

A person should read the pack before it leaves your hands. See it work: `npm run demo:canary` plants nine fake secrets in a hostile workflow, shows none survive into the pack, then pastes secrets into the finished files and shows the final scan catching them with file and line.

## Live mode safety

GET requests only, to `/api/v1/workflows`. The key goes in one `X-N8N-API-KEY` header, never in a URL, never logged, and is scrubbed from every error message. Redirects are not followed (`redirect: manual`), so a misconfigured URL cannot forward your key to another host. `http://` is accepted only for localhost.

## Optional AI summary

`--llm` adds a short summary per workflow, labelled "unverified". It uses a free option, first match wins: `HANDOVER_OLLAMA_MODEL` (local Ollama, `OLLAMA_HOST` optional), `GROQ_API_KEY`, or `GEMINI_API_KEY`. The model receives only node names, node types and connections: no parameters, credentials, URLs or pinned data. The reply is scrubbed like any other text. If the call fails, the pack is built without it.

## "When it breaks" runbook

Generated from node types by a fixed rule table in [src/rules.js](src/rules.js) (Google and Microsoft OAuth, LLM providers, databases, chat, email, CMS, generic HTTP, plus webhook, schedule, Code, sub-workflow and AI agent notes). It lists likely failures and the node names to open. It does not know your systems; treat it as a starting checklist.

## Limits

- It reads workflow structure, not run history. It cannot tell you whether a workflow actually works today.
- Plain-English text is rule-based. Expect "Edit Fields (Set), sets 3 field(s)", not business meaning. Sticky notes are copied in, so write good ones.
- Unknown or community nodes get a generic entry: the service name is guessed from the credential type.
- Cron reading covers common shapes; unusual expressions are shown raw.
- Secret detection is pattern-based. It will miss some secrets and may flag or redact a few harmless strings (a long mixed-case identifier in a node name, for example).
- Very large workflows produce large diagrams; Mermaid limits are raised but readability drops past roughly 100 nodes.
- Tested against synthetic fixtures covering n8n 1.x and 2.x workflow shapes. One dated live check: 2026-10-25, a self-hosted n8n with 97 workflows (1,526 nodes), read-only; every diagram rendered in Chrome and the output was searched for credential IDs, workflow IDs, the API key and secret patterns with zero hits. n8n changes node schemas often; open an issue with a redacted export if something breaks.

## For you if

- You are a freelancer or agency handing automations to a client and want the docs to exist before the call.
- You inherit someone else's n8n and want a map and a credential checklist first.
- You need an inventory of what talks to what before you rotate keys or migrate hosts.

## Develop

```bash
npm test             # node --test, no dependencies
npm run demo         # rebuild examples/sample-pack
npm run demo:canary  # planted-secret demo of the scrubber and the final scan
```

MIT licensed, no telemetry.

---

**Need this wired into your business? SkynetLabs builds voice agents, n8n back offices and sites that convert → https://skynetjoe.com**
