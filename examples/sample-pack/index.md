# Demo Client

Generated 2026-10-25. 4 workflow(s). No credential values or IDs are included anywhere in this pack.

## Workflows

| Workflow | Active | Trigger | Services | Credentials | Error workflow | Warnings |
| --- | --- | --- | --- | --- | --- | --- |
| [Lead alerts (daily)](lead-alerts-daily.md) | yes | schedule | HTTP API (custom endpoint), Gmail, Google Sheets | 3 | yes | 0 |
| [Support chat agent](support-chat-agent.md) | yes | webhook | OpenAI, Stripe | 2 | no | 4 |
| [Escalation to Slack](escalation-to-slack.md) | yes | subworkflow | Slack, SMTP email | 2 | no | 0 |
| [Error alert](error-alert.md) | yes | error | Telegram | 1 | is one | 0 |

## Credentials to transfer or recreate (names and types only)

| Name | Type | Used in workflow(s) |
| --- | --- | --- |
| CRM API key | httpHeaderAuth | Lead alerts (daily) |
| Owner Gmail | gmailOAuth2 | Lead alerts (daily) |
| Sheets (agency) | googleSheetsOAuth2Api | Lead alerts (daily) |
| OpenAI (client) | openAiApi | Support chat agent |
| Stripe read-only | httpHeaderAuth | Support chat agent |
| Slack bot | slackApi | Escalation to Slack |
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

- Support chat agent: Webhook "Chat webhook" has no authentication: anyone who knows the URL can trigger it.
- Support chat agent: Pinned (frozen) test data exists on 1 node(s): Chat webhook. Pinned data replaces live output during manual test runs and can contain real customer data. Unpin before sharing the export.
- Support chat agent: 1 possible hard-coded secret(s) found inside node parameters (listed by location, values masked). Move them to credentials or environment variables.
- Support chat agent: 1 disabled node(s) are part of this workflow and are excluded from the service list.
