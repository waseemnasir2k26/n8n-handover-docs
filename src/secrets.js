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

// Quoted key=value / "key": "value" assignments (JSON bodies, Code nodes).
const ASSIGN =
  /\b((?:[a-z0-9]{0,20}[_-])?(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd|token)(?:[_-][a-z0-9]{0,20})?)["']?\s*[:=]\s*["']([^"'\s{}$=][^"'\s]{7,200})["']/gi;
const URL_SECRET =
  /[?&](api[_-]?key|apikey|access[_-]?token|token|key|secret|auth|password)=([^&\s"'{}$]{8,200})/gi;

// Unquoted `key: value`, `key=value`, `key is value`, `key - value` in free text, YAML, .env lines.
const KW =
  "(?:password|passwd|pwd|pw|secret|token|api[_-]?key|apikey|auth|bearer|private[_-]?key|client[_-]?secret|access[_-]?key)";
const FREE_ASSIGN = new RegExp(
  `\\b((?:[a-z0-9]{1,20}[_-]){0,3}${KW}(?:[_-][a-z0-9]{1,20}){0,3})\\b["']?[ \\t]*(:|=|\\bis\\b|(?<=[ \\t])[-–—](?=[ \\t]))[ \\t]*["']?([^\\s"',;]{4,200})`,
  "gi",
);
// Authorization: Token abc / Authorization=Bearer abc
const AUTH_HDR =
  /\b(authorization)\b["']?\s*[:=]\s*["']?(?:(?:token|bearer|basic|apikey|key)\s+)?([^\s"',;]{4,300})/gi;

const SENSITIVE_KEY =
  /^(?:x-)?(?:api[-_ ]?key|apikey|access[-_ ]?token|auth[-_ ]?token|token|secret|client[-_ ]?secret|password|passwd|authorization|auth|private[-_ ]?key)$/i;

const PLACEHOLDER =
  /^(?:<.*>|your[_-]|xxx+|\*+|changeme|example|placeholder|todo|null|undefined|true|false|\.\.\.)/i;

const stats = { redactions: 0 };
const STRONG_KEY =
  /(?:^|[_-])(?:password|passwd|pwd|pw|secret|api[_-]?key|apikey|private[_-]?key|access[_-]?key)$/i;

function isExpression(v) {
  return v.startsWith("=") || /\{\{[\s\S]*\}\}/.test(v);
}

function looksSecretValue(v) {
  if (v.length < 8 || /\s/.test(v)) return false;
  if (isExpression(v) || PLACEHOLDER.test(v)) return false;
  if (/^https?:\/\//i.test(v) && !/[?&@]/.test(v)) return false;
  return true;
}

function strongValue(v) {
  return (
    /\d/.test(v) ||
    /[^A-Za-z0-9]/.test(v) ||
    (/[a-z]/.test(v) && /[A-Z]/.test(v) && v.length >= 8)
  );
}

function maskDesc(len) {
  return `[masked, ${len} chars]`;
}

function entropy(s) {
  const f = new Map();
  for (const c of s) f.set(c, (f.get(c) || 0) + 1);
  let h = 0;
  for (const n of f.values()) h -= (n / s.length) * Math.log2(n / s.length);
  return h;
}

/** High-entropy token: >= 20 chars, mixed classes. */
function tokenLike(t) {
  if (t.length < 20 || t.startsWith("[")) return false;
  if (/^[0-9a-f]{32,}$/i.test(t)) return true;
  return (
    /[A-Z]/.test(t) &&
    /[a-z]/.test(t) &&
    (t.match(/[0-9]/g) || []).length >= 2 &&
    entropy(t) >= 3.3
  );
}

const TOKEN_RUN = /[A-Za-z0-9_+=-]{20,}/g;

function freeHit(key, sep, val, mode) {
  if (
    /^\[/.test(val) ||
    /^[{$<]/.test(val) ||
    val.startsWith("=") ||
    PLACEHOLDER.test(val)
  )
    return false;
  if (mode === "code") {
    if (/[(){}[\]$]/.test(val) || !looksSecretValue(val) || !(/[0-9]/.test(val) || /[^A-Za-z0-9_.-]/.test(val) || (/[a-z]/.test(val) && /[A-Z]/.test(val) && val.length >= 8)))
      return false;
    if (/^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)+$/.test(val)) return false;
    return true;
  }
  if (sep === ":" || sep === "=")
    return strongValue(val) || STRONG_KEY.test(key);
  return strongValue(val);
}

/**
 * Find hard-coded secrets in node parameters. Reports LOCATION only.
 * @returns {{node:string,path:string,kind:string,len:number}[]}
 */
function findSecrets(nodeName, parameters) {
  const out = [];
  const seen = new Set();
  const add = (path, kind, len) => {
    const k = `${path}|${len}`;
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
    let m;
    ASSIGN.lastIndex = 0;
    while ((m = ASSIGN.exec(s))) {
      if (looksSecretValue(m[2]))
        add(path, `assignment to "${m[1].slice(0, 40)}"`, m[2].length);
    }
    FREE_ASSIGN.lastIndex = 0;
    while ((m = FREE_ASSIGN.exec(s))) {
      if (freeHit(m[1], m[2], m[3], "code"))
        add(path, `unquoted assignment to "${m[1].slice(0, 40)}"`, m[3].length);
    }
    AUTH_HDR.lastIndex = 0;
    while ((m = AUTH_HDR.exec(s))) {
      if (!/^[{$[<]/.test(m[2]) && m[2].length >= 8 && !isExpression(m[2]))
        add(path, "Authorization header value", m[2].length);
    }
    URL_SECRET.lastIndex = 0;
    while ((m = URL_SECRET.exec(s))) {
      if (looksSecretValue(m[2]))
        add(path, `secret in URL query "${m[1].slice(0, 30)}"`, m[2].length);
    }
  });
  return out;
}

/**
 * Replace anything secret-looking in free text before it is written anywhere.
 * opts.entropy=false for machine identifiers (node types, credential types).
 */
function scrubText(text, opts = {}) {
  const before = clean(text);
  let s = before;
  for (const [, re] of VALUE_PATTERNS) {
    re.lastIndex = 0;
    s = s.replace(re, "[REDACTED]");
  }
  s = s.replace(URL_SECRET, (m) => m.replace(/=.*/, "=[REDACTED]"));
  s = s.replace(ASSIGN, (m, k) => `${k}=[REDACTED]`);
  s = s.replace(
    AUTH_HDR,
    (m, k, v) => m.slice(0, m.length - v.length) + "[REDACTED]",
  );
  s = s.replace(FREE_ASSIGN, (m, key, sep, val) =>
    freeHit(key, sep, val, "text")
      ? m.slice(0, m.length - val.length) + "[REDACTED]"
      : m,
  );
  if (opts.entropy !== false)
    s = s.replace(TOKEN_RUN, (t) => (tokenLike(t) ? "[REDACTED]" : t));
  if (s !== before) stats.redactions++;
  return s;
}

/**
 * Scan rendered output text for anything the scrubber should have caught.
 * Returns [{line, kind}] with NO values.
 */
function scanText(text) {
  const hits = [];
  const lines = String(text).split("\n");
  lines.forEach((raw, i) => {
    const line = raw
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&amp;/g, "&")
      .replace(/\\([\\`*_[\]<>|~&#+\-=.!(){}])/g, "$1");
    const add = (kind) => hits.push({ line: i + 1, kind });
    for (const [kind, re] of VALUE_PATTERNS) {
      re.lastIndex = 0;
      if (re.test(line)) add(kind);
    }
    let m;
    ASSIGN.lastIndex = 0;
    while ((m = ASSIGN.exec(line)))
      if (looksSecretValue(m[2]))
        add(`quoted assignment to "${m[1].slice(0, 30)}"`);
    FREE_ASSIGN.lastIndex = 0;
    while ((m = FREE_ASSIGN.exec(line)))
      if (freeHit(m[1], m[2], m[3], "text") && !/^\[?REDACTED/.test(m[3]))
        add(`unquoted assignment to "${m[1].slice(0, 30)}"`);
    AUTH_HDR.lastIndex = 0;
    while ((m = AUTH_HDR.exec(line)))
      if (!/^[{$[<]/.test(m[2]) && m[2].length >= 8 && !isExpression(m[2]))
        add("Authorization header value");
    URL_SECRET.lastIndex = 0;
    while ((m = URL_SECRET.exec(line)))
      if (looksSecretValue(m[2])) add("secret in URL query");
    TOKEN_RUN.lastIndex = 0;
    while ((m = TOKEN_RUN.exec(line)))
      if (tokenLike(m[0])) add("high-entropy token");
  });
  return hits;
}

const EMAIL = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}/g;
const PHONE = /(?<![\w.])\+?\d[\d ().-]{7,20}\d(?![\w])/g;

/** Hide e-mail addresses and phone numbers in free text. */
function redactContacts(text) {
  return String(text)
    .replace(EMAIL, "<email hidden>")
    .replace(PHONE, (m) =>
      /^\d{4}-\d{2}-\d{2}/.test(m) || m.replace(/\D/g, "").length < 9
        ? m
        : "<phone hidden>",
    );
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
  scanText,
  redactContacts,
  collectEnvRefs,
  maskDesc,
  VALUE_PATTERNS,
  stats,
  tokenLike,
};
