# Demo Client

Generated 2026-10-25. 5 workflow(s). Credential values and IDs are never copied into this pack.

> **Note:** Best-effort: read every pack before you send it to a client. 1 sticky note(s) hidden (use --include-notes to include them; they are then redacted best-effort). 1 name(s) were partly replaced with \[redacted\] because they looked sensitive. This pack is best-effort: it was scanned by an independent detector before writing, but read it before you send it. independent gitleaks scan: run, no findings.

## What was redacted or hidden

| Kind | Count |
| --- | --- |
| Sticky notes hidden | 1 |
| Notes with a value replaced by \[redacted\] | 0 |
| Names with a value replaced by \[redacted\] | 1 |
| Identifiers replaced by "custom" (types, variable names) | 0 |
| Webhook paths shortened | 1 |
| Hard-coded secrets found in parameters (location only, never copied) | 1 |
| URLs hidden in names and notes | 0 |
| E-mails and phone numbers hidden in notes | 0 |

## Workflows

| Workflow | Active | Trigger | Services | Credentials | Error workflow | Warnings |
| --- | --- | --- | --- | --- | --- | --- |
| [Lead alerts (daily)](lead-alerts-daily.md) | yes | schedule | HTTP API (custom endpoint), Gmail, Google Sheets | 3 | yes | 0 |
| [Support chat agent](support-chat-agent.md) | yes | webhook | OpenAI, Stripe | 2 | no | 4 |
| [Escalation to Slack](escalation-to-slack.md) | yes | subworkflow | Slack, SMTP email | 2 | no | 0 |
| [Error alert](error-alert.md) | yes | error | Telegram | 1 | is one | 0 |
| [CRM sync (hourly)](crm-sync-hourly.md) | yes | schedule | HTTP API (custom endpoint), Slack | 2 | yes | 0 |

## Credentials to transfer or recreate (names and types only)

| Name | Type | Used in workflow(s) |
| --- | --- | --- |
| CRM API key | httpHeaderAuth | Lead alerts (daily), CRM sync (hourly) |
| Owner Gmail | gmailOAuth2 | Lead alerts (daily) |
| Sheets (agency) | googleSheetsOAuth2Api | Lead alerts (daily) |
| OpenAI (client) | openAiApi | Support chat agent |
| Stripe read-only | httpHeaderAuth | Support chat agent |
| Slack bot | slackApi | Escalation to Slack, CRM sync (hourly) |
| SMTP relay | smtp | Escalation to Slack |
| Alert bot | telegramApi | Error alert |

## Environment variables and n8n variables to set

| Name | Used in workflow(s) |
| --- | --- |
| $env.CRM\_TENANT | Lead alerts (daily) |
| $env.ALERT\_CHAT\_ID | Error alert |

## Workflow-to-workflow calls

| Caller | Node | Calls |
| --- | --- | --- |
| Support chat agent | Escalate to human | Escalation to Slack |

## Needs attention before handover

- “Support chat agent”: Webhook “Chat webhook” has no authentication: anyone who knows the URL can trigger it.
- “Support chat agent”: Pinned (frozen) test data exists on 1 node(s): Chat webhook. Pinned data replaces live output during manual test runs and can contain real customer data. Unpin before sharing the export.
- “Support chat agent”: 1 possible hard-coded secret(s) found inside node parameters (listed by location, values masked). Move them to credentials or environment variables.
- “Support chat agent”: 1 disabled node(s) are part of this workflow and are excluded from the service list.
