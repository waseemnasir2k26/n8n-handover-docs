"use strict";
// Deterministic rule table: node type -> external service + failure category,
// and failure category -> likely failures. No network, no LLM.

// [regex on lowercased short node type, service name, category]
const SERVICE_RULES = [
  [/^gmail/, "Gmail", "oauth-google"],
  [/^googlesheets/, "Google Sheets", "oauth-google"],
  [/^googledrive/, "Google Drive", "oauth-google"],
  [/^googlecalendar/, "Google Calendar", "oauth-google"],
  [/^googledocs/, "Google Docs", "oauth-google"],
  [/^googleslides/, "Google Slides", "oauth-google"],
  [/^googlebigquery/, "Google BigQuery", "oauth-google"],
  [/^googletasks/, "Google Tasks", "oauth-google"],
  [/^googlecontacts/, "Google Contacts", "oauth-google"],
  [/^googleanalytics/, "Google Analytics", "oauth-google"],
  [/^youtube/, "YouTube", "oauth-google"],
  [
    /^(lmchat|lm|embeddings)?googlegemini|^googlegemini|^(lmchat|embeddings)googlevertex/,
    "Google Gemini",
    "llm",
  ],
  [
    /^(lmchat|lm|embeddings)?openai|^openai|^lmchatopenai|^embeddingsopenai/,
    "OpenAI",
    "llm",
  ],
  [/^(lmchat|lm)?anthropic|^anthropic/, "Anthropic", "llm"],
  [/^lmchatgroq/, "Groq", "llm"],
  [/^(lmchat|lm|embeddings)ollama/, "Ollama (self-hosted)", "llm-local"],
  [/^(lmchat|embeddings)mistral/, "Mistral", "llm"],
  [/^lmchatopenrouter/, "OpenRouter", "llm"],
  [/^lmchatdeepseek/, "DeepSeek", "llm"],
  [/^lmchatxai/, "xAI", "llm"],
  [/^(lmchat|embeddings)azure/, "Azure OpenAI", "llm"],
  [/^lmchatawsbedrock|^embeddingsawsbedrock/, "AWS Bedrock", "llm"],
  [/^(lmchat|embeddings)cohere|^rerankercohere/, "Cohere", "llm"],
  [/^(lmchat|embeddings|lm)huggingface/, "Hugging Face", "llm"],
  [/^slack/, "Slack", "chat"],
  [/^telegram/, "Telegram", "chat"],
  [/^discord/, "Discord", "chat"],
  [/^whatsapp/, "WhatsApp", "chat"],
  [/^twilio/, "Twilio", "chat"],
  [/^mattermost/, "Mattermost", "chat"],
  [/^googlechat/, "Google Chat", "oauth-google"],
  [/^microsoftteams/, "Microsoft Teams", "oauth-ms"],
  [/^microsoftoutlook/, "Microsoft Outlook", "oauth-ms"],
  [/^microsoftexcel/, "Microsoft Excel", "oauth-ms"],
  [/^microsoftonedrive/, "Microsoft OneDrive", "oauth-ms"],
  [/^microsoftsharepoint/, "Microsoft SharePoint", "oauth-ms"],
  [/^microsoftsql/, "Microsoft SQL Server", "db"],
  [/^(postgres|memorypostgreschat|vectorstorepgvector)/, "PostgreSQL", "db"],
  [/^(mysql)/, "MySQL", "db"],
  [/^(mongodb|vectorstoremongodb)/, "MongoDB", "db"],
  [/^(redis|memoryredischat)/, "Redis", "db"],
  [/^(supabase|vectorstoresupabase)/, "Supabase", "db"],
  [/^(qdrant|vectorstoreqdrant)/, "Qdrant", "apikey"],
  [/^(vectorstorepinecone|pinecone)/, "Pinecone", "apikey"],
  [/^(vectorstoreweaviate)/, "Weaviate", "apikey"],
  [/^(vectorstorechroma)/, "Chroma", "apikey"],
  [/^elasticsearch/, "Elasticsearch", "db"],
  [/^airtable/, "Airtable", "apikey"],
  [/^notion/, "Notion", "apikey"],
  [/^baserow/, "Baserow", "apikey"],
  [/^nocodb/, "NocoDB", "apikey"],
  [/^hubspot/, "HubSpot", "apikey"],
  [/^salesforce/, "Salesforce", "oauth"],
  [/^pipedrive/, "Pipedrive", "apikey"],
  [/^(highlevel|gohighlevel|ghl)/, "GoHighLevel", "apikey"],
  [/^stripe/, "Stripe", "apikey"],
  [/^paypal/, "PayPal", "apikey"],
  [/^quickbooks/, "QuickBooks", "oauth"],
  [/^xero/, "Xero", "oauth"],
  [/^shopify/, "Shopify", "cms"],
  [/^woocommerce/, "WooCommerce", "cms"],
  [/^wordpress/, "WordPress", "cms"],
  [/^github/, "GitHub", "apikey"],
  [/^gitlab/, "GitLab", "apikey"],
  [/^jira/, "Jira", "apikey"],
  [/^trello/, "Trello", "apikey"],
  [/^asana/, "Asana", "apikey"],
  [/^clickup/, "ClickUp", "apikey"],
  [/^linear/, "Linear", "apikey"],
  [/^zendesk/, "Zendesk", "apikey"],
  [/^freshdesk/, "Freshdesk", "apikey"],
  [/^intercom/, "Intercom", "apikey"],
  [/^typeform/, "Typeform", "apikey"],
  [/^calendly/, "Calendly", "apikey"],
  [/^zoom/, "Zoom", "oauth"],
  [/^sendgrid/, "SendGrid", "mail"],
  [/^mailchimp/, "Mailchimp", "mail"],
  [/^mailgun/, "Mailgun", "mail"],
  [/^(brevo|sendinblue)/, "Brevo", "mail"],
  [/^emailsend/, "SMTP email", "mail"],
  [/^emailreadimap/, "IMAP mailbox", "mail"],
  [/^(facebook|instagram)/, "Meta (Facebook/Instagram)", "oauth"],
  [/^linkedin/, "LinkedIn", "oauth"],
  [/^twitter/, "X (Twitter)", "oauth"],
  [/^reddit/, "Reddit", "oauth"],
  [/^awss3|^aws/, "AWS", "apikey"],
  [/^dropbox/, "Dropbox", "oauth"],
  [/^box$/, "Box", "oauth"],
  [/^nextcloud/, "Nextcloud", "apikey"],
  [/^ftp/, "FTP/SFTP server", "files"],
  [/^ssh/, "SSH server", "files"],
  [/^elevenlabs/, "ElevenLabs", "apikey"],
  [/^perplexity/, "Perplexity", "llm"],
  [
    /^firecrawl|^apify|^serpapi|^toolserpapi/,
    "Web scraping/search API",
    "apikey",
  ],
  [/^deepl/, "DeepL", "apikey"],
  [/^(mcpclient|toolmcp)/, "MCP server", "http"],
  [/^(httprequest|toolhttprequest|graphql)/, "HTTP API", "http"],
  [/^rssfeedread/, "RSS feed", "http"],
];

const KNOWN_HOSTS = [
  [/(^|\.)openai\.com$/, "OpenAI", "llm"],
  [/(^|\.)anthropic\.com$/, "Anthropic", "llm"],
  [/generativelanguage\.googleapis\.com$/, "Google Gemini", "llm"],
  [/(^|\.)googleapis\.com$/, "Google APIs", "oauth-google"],
  [/(^|\.)groq\.com$/, "Groq", "llm"],
  [/(^|\.)openrouter\.ai$/, "OpenRouter", "llm"],
  [/(^|\.)mistral\.ai$/, "Mistral", "llm"],
  [/(^|\.)cerebras\.ai$/, "Cerebras", "llm"],
  [/(^|\.)perplexity\.ai$/, "Perplexity", "llm"],
  [/(^|\.)elevenlabs\.io$/, "ElevenLabs", "apikey"],
  [/(^|\.)slack\.com$/, "Slack", "chat"],
  [/(^|\.)telegram\.org$/, "Telegram", "chat"],
  [/(^|\.)discord(app)?\.com$/, "Discord", "chat"],
  [/(^|\.)twilio\.com$/, "Twilio", "chat"],
  [/(^|\.)stripe\.com$/, "Stripe", "apikey"],
  [/(^|\.)github\.com$/, "GitHub", "apikey"],
  [/(^|\.)facebook\.com$/, "Meta Graph API", "oauth"],
  [/(^|\.)(twitter|x)\.com$/, "X (Twitter)", "oauth"],
  [/(^|\.)linkedin\.com$/, "LinkedIn", "oauth"],
  [/(^|\.)notion\.com$|(^|\.)notion\.so$/, "Notion", "apikey"],
  [/(^|\.)airtable\.com$/, "Airtable", "apikey"],
  [/(^|\.)hubspot\.com$/, "HubSpot", "apikey"],
  [/(^|\.)sendgrid\.com$/, "SendGrid", "mail"],
  [/(^|\.)leadconnectorhq\.com$/, "GoHighLevel", "apikey"],
  [/(^|\.)supabase\.co$/, "Supabase", "db"],
];

const FAIL = {
  "oauth-google": [
    [
      "Auth expired or revoked",
      'Refresh token expired or revoked: password change, access removed, or (Google Cloud app left in "Testing" mode) refresh tokens expire after 7 days',
      "Reconnect the credential, then re-run the failed execution",
    ],
    [
      "429 / quota exceeded",
      "Per-minute or daily Google API quota hit, often from a loop calling the node once per item",
      "Add batching or a Wait node; check the Google Cloud console quota page",
    ],
    [
      "Schema change",
      "Sheet column renamed or moved, folder or file deleted or unshared",
      "Open the target sheet/folder and compare against the column or ID the node expects",
    ],
  ],
  "oauth-ms": [
    [
      "Auth expired or revoked",
      "Token expired, admin consent withdrawn, or the app registration secret expired",
      "Reconnect the credential; check the app registration secret expiry in Azure",
    ],
    [
      "429 / throttled",
      "Microsoft Graph throttling (honours Retry-After)",
      "Reduce call rate; add a Wait node",
    ],
    [
      "Schema change",
      "Drive item, mailbox folder or workbook table renamed or removed",
      "Verify the resource still exists",
    ],
  ],
  oauth: [
    [
      "Auth expired or revoked",
      "OAuth token expired or the user revoked app access",
      "Reconnect the credential in n8n",
    ],
    [
      "429 / rate limited",
      "Provider rate limit reached",
      "Check the provider dashboard; slow the loop down",
    ],
    [
      "Schema change",
      "Provider API version or field names changed",
      "Compare the failing node output with the provider changelog",
    ],
  ],
  apikey: [
    [
      "401 / 403 auth failure",
      "API key rotated, revoked, or the plan/permissions changed",
      "Replace the key in the credential; test the node",
    ],
    [
      "429 / rate limited",
      "Plan limit or per-minute limit reached",
      "Check provider usage page; add Wait or batching",
    ],
    [
      "Schema change",
      "Field renamed, ID deleted, or API version retired",
      "Open the failing node, run it with the last input, read the error body",
    ],
  ],
  llm: [
    [
      "401 / 403 auth failure",
      "API key rotated or billing/credit exhausted (often shown as 401 or 402)",
      "Check key and billing in the provider console; replace credential",
    ],
    [
      "429 rate limit",
      "Per-minute token or request limit, or free-tier daily cap",
      "Add retry-on-fail with a wait, reduce parallel runs, or switch model",
    ],
    [
      "Model deprecated or renamed",
      "Provider retired the model name configured in the node",
      "Pick a current model in the node settings",
    ],
    [
      "Output no longer parses",
      "Model replied in a different shape, so an output parser or the next node fails",
      "Open the failed execution, read the raw model reply, tighten the prompt/schema",
    ],
    [
      "Context too long",
      "Input grew past the model context window",
      "Truncate or summarise input before the model node",
    ],
  ],
  "llm-local": [
    [
      "Connection refused",
      "Ollama server stopped, moved, or the model was not pulled",
      "Check the Ollama host is up and the model name exists (ollama list)",
    ],
    [
      "Timeout / slow",
      "Model too large for the machine or machine busy",
      "Use a smaller model or raise the node timeout",
    ],
  ],
  db: [
    [
      "Connection refused or timeout",
      "Database restarted, host/IP allow-list changed, or pool exhausted",
      "Check the DB host is reachable from the n8n server",
    ],
    [
      "Auth failed",
      "Password rotated or user dropped",
      "Update the credential",
    ],
    [
      "Schema change",
      "Table or column renamed or dropped, or a migration ran",
      "Compare the node query/columns with the current schema",
    ],
  ],
  chat: [
    [
      "Auth failed",
      "Bot token or API key revoked/regenerated, or the bot was removed from the channel/chat",
      "Re-add the bot; replace the credential",
    ],
    [
      "429 / flood limits",
      "Provider send-rate limit (messages per second or per chat)",
      "Space out sends with a Wait node",
    ],
    [
      "Message rejected",
      "Message too long, bad formatting, or recipient opted out or is invalid",
      "Open the failed execution and read the response body",
    ],
  ],
  mail: [
    [
      "Auth failed",
      "Mailbox password or app password changed, API key rotated, or 2FA policy changed",
      "Replace the credential; for Gmail-style SMTP use an app password",
    ],
    [
      "Sending limit reached",
      "Daily send cap of the provider or mailbox reached",
      "Check provider limits; spread sends over time",
    ],
    [
      "Delivered to spam or bounced",
      "SPF/DKIM/DMARC missing or sender domain changed",
      "Check DNS records and the provider bounce log",
    ],
  ],
  cms: [
    [
      "Auth failed",
      "API key or application password revoked, or the user lost permissions",
      "Recreate the key; confirm the user role",
    ],
    [
      "429 / host limits",
      "Shop/host throttles the API",
      "Add batching; check the host logs",
    ],
    [
      "Schema change",
      "Product, post type or custom field renamed; plugin updated or removed",
      "Compare the node fields with the current site setup",
    ],
  ],
  files: [
    [
      "Connection or auth failed",
      "Server moved, key/password rotated, or firewall changed",
      "Test the connection from the n8n server; update the credential",
    ],
    [
      "Path missing",
      "Remote folder or file renamed or removed",
      "Check the remote path configured in the node",
    ],
  ],
  http: [
    [
      "401 / 403",
      "Token expired, key rotated, or header/auth settings changed",
      "Check the credential attached to the request node",
    ],
    [
      "429 / 5xx / timeout",
      "Remote API is rate limiting or down",
      "Use retry-on-fail with wait; read Retry-After in the failed execution",
    ],
    [
      "Response shape changed",
      "A field was renamed, so expressions downstream return undefined or empty",
      "Open the failed execution, compare the response with the field the next node reads",
    ],
    [
      "DNS / TLS error",
      "Endpoint moved or its certificate expired",
      "Open the URL from the n8n server",
    ],
  ],
};

// Built-in node notes (not external services).
const BUILTIN_NOTES = {
  schedule: [
    "Run did not fire",
    "Workflow is inactive (it deactivates if saved with errors, or after import), n8n was down at the scheduled time (missed runs are not replayed), or the timezone differs from what you expect",
    "Check the workflow Active toggle, the n8n timezone setting, and Executions around the expected time",
  ],
  webhook: [
    "Webhook not reached or returns 404",
    "Workflow inactive, or the sender uses the test URL instead of the production URL, or the path changed",
    "Check Active toggle and the method and path shown in this document (path shortened unless --show-webhook-paths)",
  ],
  "webhook-open": [
    "Anyone who knows the URL can trigger it",
    "Webhook has no authentication configured",
    "Add header or basic auth on the Webhook node, or validate a shared secret in the first node",
  ],
  code: [
    "Code node throws",
    "Input shape changed upstream (undefined property), or very large item counts",
    "Open the failed execution; the error names the line. Check the node output before it",
  ],
  subworkflow: [
    "Sub-workflow call fails",
    "The called workflow is inactive, renamed, deleted, or expects different input fields. Its error shows as a failure of the caller",
    "Open the called workflow and its latest execution; compare input fields",
  ],
  agent: [
    "AI agent loops, stalls or returns nonsense",
    "Iteration cap reached, a tool errored, or the model passed bad arguments to a tool",
    "Open the failed execution and read the agent step-by-step log; check each tool node separately",
  ],
  execcmd: [
    "Command fails",
    "Binary missing or permissions changed on the n8n host, or command output format changed",
    "Run the same command by hand on the n8n host",
  ],
};

// Types that never count as an external service
const INTERNAL = new Set([
  "set",
  "if",
  "switch",
  "merge",
  "code",
  "function",
  "functionitem",
  "noop",
  "wait",
  "splitinbatches",
  "filter",
  "sort",
  "limit",
  "aggregate",
  "itemlists",
  "splitout",
  "summarize",
  "removeduplicates",
  "datetime",
  "crypto",
  "html",
  "xml",
  "markdown",
  "stickynote",
  "manualtrigger",
  "scheduletrigger",
  "cron",
  "interval",
  "executeworkflow",
  "executeworkflowtrigger",
  "errortrigger",
  "respondtowebhook",
  "webhook",
  "stoperror",
  "stopanderror",
  "converttofile",
  "extractfromfile",
  "compression",
  "readwritefile",
  "executecommand",
  "start",
  "editimage",
  "renamekeys",
  "comparedatasets",
  "agent",
  "chainllm",
  "chainsummarization",
  "chainretrievalqa",
  "informationextractor",
  "sentimentanalysis",
  "textclassifier",
  "memorybufferwindow",
  "textsplitterrecursivecharactertextsplitter",
  "outputparserstructured",
  "outputparserautofixing",
  "toolcode",
  "toolworkflow",
  "toolcalculator",
  "toolthink",
  "chattrigger",
  "formtrigger",
  "form",
  "chat",
  "evaluation",
  "documentdefaultdatadloader",
  "documentdefaultdataloader",
  "retrievervectorstore",
  "mcptrigger",
  "datatable",
  "wait",
  "n8n",
  "n8ntrigger",
  "debughelper",
  "readbinaryfile",
  "writebinaryfile",
  "spreadsheetfile",
  "movebinarydata",
  "ical",
  "jwt",
  "totp",
]);

function shortType(type) {
  return String(type || "")
    .split(".")
    .pop();
}

function titleFromCamel(s) {
  return String(s)
    .replace(/(OAuth2Api|OAuth2|Oauth2|Api|Trigger|Tool)$/g, "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/^./, (c) => c.toUpperCase())
    .trim();
}

/** @returns {{service:string,cat:string}|null} */
const LABELS = {
  httpRequest: 'HTTP Request', httpRequestTool: 'HTTP Request tool', scheduleTrigger: 'Schedule trigger', manualTrigger: 'Manual trigger',
  webhook: 'Webhook', respondToWebhook: 'Respond to Webhook', agent: 'AI Agent', code: 'Code', if: 'IF', switch: 'Switch', set: 'Edit Fields (Set)',
  merge: 'Merge', splitInBatches: 'Loop over items (Split in Batches)', executeWorkflow: 'Execute Workflow', executeWorkflowTrigger: 'Execute Workflow trigger',
  errorTrigger: 'Error trigger', noOp: 'No Operation', emailSend: 'Send Email (SMTP)', emailReadImap: 'Email trigger (IMAP)', toolWorkflow: 'Call workflow (AI tool)',
  toolCode: 'Code (AI tool)', chainLlm: 'Basic LLM chain', memoryBufferWindow: 'Window buffer memory', stickyNote: 'Sticky note',
};

function typeLabel(short) {
  if (LABELS[short]) return LABELS[short];
  let m;
  if ((m = /^lmChat(.+)$/.exec(short))) return fixCase(titleFromCamel(m[1])) + ' chat model';
  if ((m = /^lm(.+)$/.exec(short)) && /^[A-Z]/.test(m[1])) return fixCase(titleFromCamel(m[1])) + ' model';
  if ((m = /^embeddings(.+)$/.exec(short))) return fixCase(titleFromCamel(m[1])) + ' embeddings';
  if ((m = /^memory(.+)$/.exec(short))) return fixCase(titleFromCamel(m[1])) + ' memory';
  if ((m = /^vectorStore(.+)$/.exec(short))) return fixCase(titleFromCamel(m[1])) + ' vector store';
  if ((m = /^(.+)Tool$/.exec(short)) && !/Trigger$/.test(short)) return fixCase(titleFromCamel(m[1])) + ' (AI tool)';
  return fixCase(titleFromCamel(short)) || short;
}

function fixCase(s) {
  return String(s).replace(/\bOpen Ai\b/g, 'OpenAI').replace(/\bHttp\b/g, 'HTTP').replace(/\bAi\b/g, 'AI').replace(/\bSmtp\b/g, 'SMTP').replace(/\bImap\b/g, 'IMAP').replace(/\bGoogle Gemini\b/g, 'Gemini').replace(/\bAws\b/g, 'AWS').replace(/\bMy Sql\b/g, 'MySQL').replace(/\bPostgres\b/g, 'PostgreSQL').replace(/\bMongo Db\b/g, 'MongoDB');
}

function classify(type, credTypes = []) {
  const s = shortType(type).toLowerCase();
  for (const [re, service, cat] of SERVICE_RULES) {
    if (re.test(s)) return { service, cat };
  }
  if (INTERNAL.has(s)) return null;
  if (credTypes.length) {
    return {
      service: titleFromCamel(credTypes[0]) || titleFromCamel(shortType(type)),
      cat: /oauth/i.test(credTypes[0]) ? "oauth" : "apikey",
      derived: true,
    };
  }
  return null;
}

function classifyHost(host) {
  const h = String(host || "").toLowerCase();
  for (const [re, service, cat] of KNOWN_HOSTS) {
    if (re.test(h)) return { service, cat };
  }
  return null;
}

module.exports = {
  SERVICE_RULES,
  FAIL,
  BUILTIN_NOTES,
  classify,
  classifyHost,
  shortType,
  titleFromCamel,
  typeLabel,
  INTERNAL,
};
