# Changelog

## 1.0.0 - 2026-10-25

- First release: handover pack from exported workflow JSON or the live n8n public API (read-only).
- Per workflow: plain-English summary, triggers and schedule (cron translated), steps, Mermaid flowchart with labelled branches and AI sub-node links, services, credential names and types, env vars, webhooks, error handling, caps, sub-workflows, warnings, "When it breaks" runbook.
- Outputs: `index.html` (print CSS), `index.md`, `<workflow>.md`, `inventory.csv`.
- Optional `--llm` summaries via Ollama, Groq or Gemini (structure only).
- Redaction: no credential values or IDs, secrets masked by location, hosts hidden unless `--show-hosts`.
