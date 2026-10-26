# Changelog

## 1.0.4 - 2026-10-26

- Fixed a false block (exit 3) on documented-safe names. `examples/workflows/01-lead-alerts.json` with only the workflow name set to `Secret Key - Rotation`, `Credentials - Slack`, `Password - Reset Flow`, `Key Accounts: weekly sync`, `Key Results: Q4 review`, `Token: refresh job` or `Secret Sauce - Recipe` now exits 0 and writes the name verbatim. Cause: the final gate judged a label phrase over the whole CSV line, so the value-looking words of the NEXT column (`"CRM API key"`, `"Owner Gmail"`) completed the label. Correction to 1.0.3: `Secret Key - Rotation` was blocked in the 1.0.3 build too (exit 3, `inventory.csv:4`); the 1.0.3 entry above was wrong to say it was not reproduced.
- Gate: CSV files are parsed with RFC 4180 quoting and every field is judged alone; markdown and HTML lines are judged per line, with table cells and tags as breaks, as before. The label rules in `src/value-rule.js` are unchanged. A secret in any single CSV column still exits 3.
- Leak cases still hold: `Password - Slack abc123xyz`, `Token - Sheet Zx9Kq2`, `Secret: Slack 7f3a9b2c` and `Key Accounts - Tangerine` are redacted in the name (exit 0, the value is not written).
- Tests: `test/round9.test.js` (the seven names through the full pipeline; 21 next-column cases; a secret in each of the six columns; quoted CSV fields; table and tag boundaries).
- Limit (documented in README): a label in one CSV column and its value in the next column are not joined.

## 1.0.3 - 2026-10-26

- Fixed a leak: `Password - Slack abc123xyz` kept `abc123xyz` (the rule checked only the first word after the dash). The dash, colon and `=` rules now check every word after the label. A name keeps the rest only when every word is a safe word (letters only, at most 12 letters, no capital after the first letter, or an allow-listed noun, or a reporting period Q1-Q4 / H1-H2 / FY26). Any other word makes the whole rest the value: `Password - Slack abc123xyz` becomes `Password - [redacted]`, `Token - Sheet Zx9Kq2` becomes `Token - [redacted]`, `Secret: Slack 7f3a9b2c` becomes `Secret: [redacted]`.
- Kept as before: `Password - Reset Flow`, `Credentials - Slack`, `Key Accounts: weekly sync`, `Password - Slack Reset Flow`, `PIN Code Generator - Sheet`, `Secret Key - Rotation`, `Key Results: Q3 Growth`. A single word after a dash still needs the allow-list (`Password - Zebra` is redacted).
- Changed: `Nightly backup password: Winter2026!! then email` now redacts `then email` too (the remainder holds an unsafe word, so it is the value). A remainder of safe words only keeps them.
- Gate: a table cell (`|`) ends a name; a markdown link target (`[Auth - Callback](auth-callback.md)`) and a CSV mark (`"Credentials - Slack","true"`) are not part of the name.
- Fuzz: 216 new shapes `<label> - <allow-listed noun> <random value>` (labels Password, Secret, Token, API Key; separators `-`, `:`, en dash; values abc123xyz, Zx9Kq2, 7f3a9b2c). `npm run fuzz` now plants 3057 cases, 0 leaks with exit 0; 244 injected cases stopped by the gate.
- Correction to 1.0.2: `Secret Key - Rotation` is kept (exit 0), as the 1.0.2 entry said. It was not reproduced as exit 3 in this release's checks.
- `test/round8.test.js` covers the regressions above.

## 1.0.2 - 2026-10-26

- Dash rule fails closed: after a label phrase and a dash, ONE token that ends the name is redacted unless it is an allow-listed workflow noun (sheet, recipe, flow, sync, slack, reset, rotation, ...) or an n8n node type name in the workflow. `Key Accounts - Tangerine`, `Secret Santa - Tangerine`, `Password - Zebra` are redacted; `PIN Code Generator - Sheet`, `Secret Sauce - Recipe`, `Credentials - Slack`, `Password - Reset Flow` stay. ":" and "=" are unchanged.
- Changed from 1.0.1: `Key Accounts - Quarterly` is now redacted (a Title Case name word is no longer kept), and `Secret Key - Rotation` is kept (`rotation` is an allow-listed noun).

## 1.0.1 - 2026-10-26

- Dash form of an allow-listed phrase redacts its value: `Key Accounts - tangerine`, `Secret Santa - tangerine` (also en and em dash). Two or more words after the dash stay a name (`Key Accounts - weekly sync`). The file name comes from the redacted name.
- `inventory.csv` is written with LF line endings (matches `.gitattributes`), so `npm run demo` leaves no git diff.
- `.gitleaksignore` comments no longer contain token-shaped fixtures; fingerprints added so `gitleaks detect` (git and `--no-git`) exits 0.

## 1.0.0 - 2026-10-25

- First release: handover pack from exported workflow JSON or the live n8n public API (read-only).
- Per workflow: plain-English summary, triggers and schedule (cron translated), steps, Mermaid flowchart with labelled branches and AI sub-node links, services, credential names and types, env vars, webhooks, error handling, caps, sub-workflows, warnings, "When it breaks" runbook.
- Outputs: `index.html` (print CSS), `index.md`, `<workflow>.md`, `inventory.csv`.
- Optional `--llm` summaries via Ollama, Groq or Gemini (structure only).
- Redaction: no credential values or IDs, secrets masked by location, hosts hidden unless `--show-hosts`.
- Final scan of every rendered file with the full secret detector (exit 3 and nothing written unless `--allow-findings`).
- Free-text scrubbing for unquoted `key: value`, `key is value`, `Authorization: Token x`, and high-entropy tokens; webhook paths shortened unless `--show-webhook-paths`; e-mails and phone numbers hidden in sticky notes (`--redact-contacts`, `--keep-contacts`).
- `npm run demo:canary`, `--diagram-fallback`, clear "Folder not found" message.
- Rebuilt free-text handling as default-deny: sticky notes hidden unless `--include-notes`; names pass a normalising name policy; parameter text limited to fixed vocabularies.
- Independent final gate (token classifier with base64/URL decoding, plus gitleaks when installed); exit 3 on any hit.
- `npm run fuzz` adversarial corpus (800+ cases, 0 leaks with exit 0), `.gitattributes` eol=lf, local date and time zone in the pack header.
- Name policy precision: credential words match whole tokens in 14 languages, only the value is redacted ("Send Token Report" stays), names stay distinguishable, files are safe words + short hash, counters count real redactions only. 65-name usefulness corpus: 0 false redactions.
- Gate and scrubber: script-agnostic token checks, spaced digit runs, cards/IBANs, whole-name short passwords, connection and node types sanitised, gitleaks fails closed when broken and is flagged in the header when absent.
