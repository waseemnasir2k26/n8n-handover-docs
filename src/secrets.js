"use strict";
const { walkStrings, clean } = require("./util");

// Value-level patterns. All quantifiers are bounded to stay ReDoS-safe.
const VALUE_PATTERNS = [
  ["OpenAI/Anthropic-style key", /\bsk-[A-Za-z0-9_-]{16,200}/g],
  [
    "GitHub token",
    /\b(?:gh[pousr]_[A-Za-z0-9]{30,100}|github_pat_[A-Za-z0-9_]{30,120})/g,
  ],
  ["Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,100}/g],
  [
    "Slack webhook URL",
    /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,100}/g,
  ],
  [
    "Discord webhook URL",
    /discord(?:app)?\.com\/api\/webhooks\/\d{5,25}\/[\w-]{20,100}/g,
  ],
  ["AWS access key id", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ["Groq key", /\bgsk_[A-Za-z0-9]{20,100}/g],
  ["Stripe key", /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,100}/g],
  ["JWT", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,200}/g],
  ["Bearer token", /\bBearer\s+[A-Za-z0-9._~+/=-]{16,300}/gi],
  ["Basic auth header", /\bBasic\s+[A-Za-z0-9+/]{16,300}={0,2}/g],
  ["Telegram bot token", /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g],
  ["Private key block", /-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----/g],
  [
    "Credentials in URL",
    /\b[a-z][a-z0-9+.-]{1,10}:\/\/[^\s/:@"']{1,64}:[^\s/@"']{3,64}@/gi,
  ],
];

// key=value / "key": "value" assignments, also inside Code nodes and JSON bodies.
const ASSIGN =
  /\b((?:[a-z0-9]{0,20}[_-])?(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd|token)(?:[_-][a-z0-9]{0,20})?)["']?\s*[:=]\s*["']([^"'\s{}$=][^"'\s]{7,200})["']/gi;
const URL_SECRET =
  /[?&](api[_-]?key|apikey|access[_-]?token|token|key|secret|auth|password)=([^&\s"'{}$]{8,200})/gi;

const SENSITIVE_KEY =
  /^(?:x-)?(?:api[-_ ]?key|apikey|access[-_ ]?token|auth[-_ ]?token|token|secret|client[-_ ]?secret|password|passwd|authorization|auth|private[-_ ]?key)$/i;

const PLACEHOLDER =
  /^(?:<.*>|your[_-]|xxx+|\*+|changeme|example|placeholder|todo|null|undefined|true|false|\.\.\.)/i;

function isExpression(v) {
  return v.startsWith("=") || /\{\{[\s\S]*\}\}/.test(v);
}

function looksSecretValue(v) {
  if (v.length < 8 || /\s/.test(v)) return false;
  if (isExpression(v) || PLACEHOLDER.test(v)) return false;
  if (/^https?:\/\//i.test(v) && !/[?&@]/.test(v)) return false;
  return true;
}

function maskDesc(len) {
  return `[masked, ${len} chars]`;
}

/**
 * Find hard-coded secrets in node parameters. Reports LOCATION only.
 * @returns {{node:string,path:string,kind:string,len:number}[]}
 */
function findSecrets(nodeName, parameters) {
  const out = [];
  const seen = new Set();
  const add = (path, kind, len) => {
    const k = `${path}|${kind}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ node: nodeName, path: clean(path), kind, len });
  };
  const scanPair = (obj, path) => {
    // {name:'Authorization', value:'...'} shapes (HTTP headers, query params)
    if (
      obj &&
      typeof obj === "object" &&
      !Array.isArray(obj) &&
      typeof obj.name === "string" &&
      typeof obj.value === "string" &&
      SENSITIVE_KEY.test(obj.name.trim()) &&
      looksSecretValue(obj.value)
    ) {
      add(
        `${path}.value`,
        `hard-coded value for "${obj.name.trim().slice(0, 40)}"`,
        obj.value.length,
      );
    }
  };
  const visit = (v, path, depth) => {
    if (depth > 14 || v == null) return;
    if (Array.isArray(v)) {
      v.forEach((x, i) => visit(x, `${path}[${i}]`, depth + 1));
      return;
    }
    if (typeof v !== "object") return;
    scanPair(v, path);
    for (const [k, val] of Object.entries(v)) {
      const p = path ? `${path}.${k}` : k;
      if (
        typeof val === "string" &&
        SENSITIVE_KEY.test(k.trim()) &&
        looksSecretValue(val)
      ) {
        add(p, `hard-coded value for "${k.slice(0, 40)}"`, val.length);
      }
      visit(val, p, depth + 1);
    }
  };
  visit(parameters, "", 0);
  walkStrings(parameters, (s, path) => {
    for (const [kind, re] of VALUE_PATTERNS) {
      re.lastIndex = 0;
      const m = re.exec(s);
      if (m) add(path, kind, m[0].length);
    }
    ASSIGN.lastIndex = 0;
    let m;
    while ((m = ASSIGN.exec(s))) {
      if (looksSecretValue(m[2]))
        add(path, `assignment to "${m[1].slice(0, 40)}"`, m[2].length);
    }
    URL_SECRET.lastIndex = 0;
    while ((m = URL_SECRET.exec(s))) {
      if (looksSecretValue(m[2]))
        add(path, `secret in URL query "${m[1].slice(0, 30)}"`, m[2].length);
    }
  });
  return out;
}

/** Replace anything secret-looking in free text before it is written anywhere. */
function scrubText(text) {
  let s = clean(text);
  for (const [, re] of VALUE_PATTERNS) {
    re.lastIndex = 0;
    s = s.replace(re, "[REDACTED]");
  }
  s = s.replace(URL_SECRET, (m) => m.replace(/=.*/, "=[REDACTED]"));
  s = s.replace(ASSIGN, (m, k) => `${k}=[REDACTED]`);
  return s;
}

/** Env var / variable references inside expressions. Names only. */
function collectEnvRefs(parameters) {
  const env = new Set();
  const vars = new Set();
  const secrets = new Set();
  walkStrings(parameters, (s) => {
    let m;
    const reEnv =
      /\$env(?:\.([A-Za-z_][A-Za-z0-9_]{0,80})|\[\s*["']([A-Za-z_][A-Za-z0-9_]{0,80})["']\s*\])/g;
    while ((m = reEnv.exec(s))) env.add(m[1] || m[2]);
    const reVars =
      /\$vars(?:\.([A-Za-z_][A-Za-z0-9_]{0,80})|\[\s*["']([A-Za-z_][A-Za-z0-9_]{0,80})["']\s*\])/g;
    while ((m = reVars.exec(s))) vars.add(m[1] || m[2]);
    const reSec =
      /\$secrets\.([A-Za-z_][A-Za-z0-9_]{0,60})\.([A-Za-z_][A-Za-z0-9_]{0,80})/g;
    while ((m = reSec.exec(s))) secrets.add(`${m[1]}.${m[2]}`);
  });
  return { env: [...env], vars: [...vars], secrets: [...secrets] };
}

module.exports = {
  findSecrets,
  scrubText,
  collectEnvRefs,
  maskDesc,
  VALUE_PATTERNS,
};
