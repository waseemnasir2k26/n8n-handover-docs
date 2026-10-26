# Changelog

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
