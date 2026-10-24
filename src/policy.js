"use strict";
// NAME POLICY: every user-written string that reaches the pack (workflow, node,
// tag, credential and sub-workflow names, and notes when --include-notes is on)
// is normalised first, then any suspicious span is replaced with [redacted].
// Over-redacting is acceptable; leaking is not. Free text is not the product.
const { VALUE_PATTERNS } = require("./secrets");
const { SERVICE_RULES } = require("./rules");

const STEMS = [
  "pass",
  "pw",
  "pwd",
  "secret",
  "token",
  "key",
  "auth",
  "cred",
  "login",
  "bearer",
  "sk-",
  "sk_",
  "private",
  "otp",
];

// Cyrillic / Greek letters that look like Latin ones. Used for MATCHING only.
const CONFUSABLES = {
  а: "a",
  е: "e",
  о: "o",
  р: "p",
  с: "c",
  у: "y",
  х: "x",
  і: "i",
  ј: "j",
  ѕ: "s",
  ԁ: "d",
  һ: "h",
  т: "t",
  к: "k",
  м: "m",
  н: "h",
  в: "b",
  А: "a",
  В: "b",
  Е: "e",
  К: "k",
  М: "m",
  Н: "h",
  О: "o",
  Р: "p",
  С: "c",
  Т: "t",
  Х: "x",
  У: "y",
  ο: "o",
  ρ: "p",
  α: "a",
  ε: "e",
  ι: "i",
  κ: "k",
  ν: "v",
  τ: "t",
  υ: "u",
  χ: "x",
  β: "b",
  η: "n",
  μ: "u",
  ω: "w",
  σ: "s",
  Α: "a",
  Β: "b",
  Ε: "e",
  Ζ: "z",
  Η: "h",
  Ι: "i",
  Κ: "k",
  Μ: "m",
  Ν: "n",
  Ο: "o",
  Ρ: "p",
  Τ: "t",
  Υ: "y",
  Χ: "x",
};
const LEET = {
  0: "o",
  1: "i",
  3: "e",
  4: "a",
  5: "s",
  7: "t",
  "@": "a",
  $: "s",
  "!": "i",
};

const ENTITY = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  colon: ":",
  lpar: "(",
  rpar: ")",
  equals: "=",
  period: ".",
  comma: ",",
  sol: "/",
  bsol: "\\",
  lowbar: "_",
  ast: "*",
  num: "#",
  excl: "!",
  commat: "@",
  dollar: "$",
  percnt: "%",
  plus: "+",
  hyphen: "-",
  dash: "-",
  semi: ";",
  lsqb: "[",
  rsqb: "]",
  lbrace: "{",
  rbrace: "}",
  vert: "|",
  grave: "`",
  Tab: " ",
  NewLine: " ",
};
const INVISIBLE = new RegExp(
  "[\\u00ad\\u034f\\u061c\\u115f\\u1160\\u17b4\\u17b5\\u180b-\\u180e\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u206f\\u3164\\ufe00-\\ufe0f\\ufeff\\uffa0]",
  "g",
);
const CTRL = new RegExp("[\\u0000-\\u001f\\u007f-\\u009f]", "g");

function cp(n) {
  try {
    return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : " ";
  } catch {
    return " ";
  }
}

function decodeOnce(s) {
  return s
    .replace(/&#x([0-9a-f]{1,6});?/gi, (m, h) => cp(parseInt(h, 16)))
    .replace(/&#(\d{1,7});?/g, (m, d) => cp(parseInt(d, 10)))
    .replace(/&([A-Za-z]{2,8});/g, (m, n) => (n in ENTITY ? ENTITY[n] : m))
    .replace(/(?:%[0-9a-f]{2})+/gi, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return m;
      }
    });
}

/** Normalise for display and matching: entities, %-encoding, NFKC, invisibles, markdown wrappers, whitespace. */
function normalise(input) {
  let s = String(input == null ? "" : input);
  if (s.length > 400000) s = s.slice(0, 400000);
  for (let i = 0; i < 3; i++) {
    const d = decodeOnce(s);
    if (d === s) break;
    s = d;
  }
  s = s.normalize("NFKC").replace(INVISIBLE, "").replace(CTRL, " ");
  s = s.replace(/\*\*|__|[`\\]/g, "").replace(/\|/g, " ");
  return s.replace(/\s+/g, " ").trim();
}

function fold(s) {
  let out = "";
  for (const ch of String(s).toLowerCase()) out += CONFUSABLES[ch] || ch;
  return out;
}
function leet(s) {
  let out = "";
  for (const ch of s) out += LEET[ch] || ch;
  return out;
}

function hasStem(tok) {
  const f = fold(tok);
  const variants = [f, leet(f), f.split("").reverse().join("")];
  for (const v of variants) {
    for (const st of STEMS) {
      if (st.length < 4 && v === variants[2]) continue; // reversed: only longer stems
      if (v.includes(st)) return true;
    }
  }
  return false;
}

function entropy(s) {
  const f = new Map();
  for (const c of s) f.set(c, (f.get(c) || 0) + 1);
  let h = 0;
  for (const n of f.values()) h -= (n / s.length) * Math.log2(n / s.length);
  return h;
}

const slugLike = (t) =>
  /^[a-z0-9]+([-.][a-z0-9]+)+$/.test(t) &&
  t
    .split(/[-.]/)
    .every((p) => p.length <= 12 && (p.match(/\d/g) || []).length <= 3);

function b64Decode(t) {
  if (!/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(t)) return null;
  try {
    const buf = Buffer.from(t.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    if (buf.length < 8) return null;
    let printable = 0;
    for (const b of buf)
      if ((b >= 32 && b < 127) || b === 10 || b === 9) printable++;
    return printable / buf.length >= 0.85 ? buf.toString("latin1") : null;
  } catch {
    return null;
  }
}

/** Token-level checks, independent of keywords. */
function tokenSuspicious(tok, depth = 0, idMode = false) {
  const t = tok.replace(/^[^A-Za-z0-9]+/, "").replace(/[.,;:)\]}>'"]+$/, "");
  if (!t) return false;
  const letters = /[A-Za-z]/.test(t);
  const digits = (t.match(/\d/g) || []).length;
  const upper = /[A-Z]/.test(t);
  const lower = /[a-z]/.test(t);
  const symbol = /[!@#$%^&*+=~?]/.test(t);
  if (idMode) {
    // machine identifiers (camelCase types like googleSheetsOAuth2Api are normal)
    if (/[0-9a-fA-F]{16,}/.test(t)) return true;
    if (t.length >= 16 && digits >= 3 && letters && !slugLike(t)) return true;
    if (t.length >= 8 && letters && digits >= 1 && symbol) return true;
    if (t.length >= 20 && entropy(t) >= 4.0 && digits >= 2) return true;
    const d = depth < 2 ? b64Decode(t) : null;
    return !!(d && (/\d/.test(d) || d.includes(":")));
  }
  if (t.length >= 12 && letters && digits >= 1 && !slugLike(t)) return true;
  if (/[0-9a-fA-F]{16,}/.test(t)) return true;
  if (t.length >= 8 && letters && digits >= 1 && symbol) return true;
  if (t.length >= 10 && upper && lower && digits >= 1 && !slugLike(t))
    return true;
  if (
    t.length >= 16 &&
    entropy(t) >= 3.5 &&
    (digits >= 1 || (upper && lower)) &&
    !slugLike(t)
  )
    return true;
  if (depth < 2) {
    const d = b64Decode(t);
    if (d && (hasStem(d) || /\d/.test(d) || d.includes(":"))) return true;
  }
  return false;
}

const redactedRe = /\[redacted\]/;

// Stems that, alone, usually only label a credential ("API key", "Gmail OAuth").
const WEAK = ["key", "token", "auth", "cred"];
function weakStemOnly(tok) {
  const f = fold(tok);
  const strong = STEMS.filter((s) => !WEAK.includes(s));
  const variants = [f, leet(f), f.split("").reverse().join("")];
  return !variants.some((v, i) =>
    strong.some((st) => !(st.length < 4 && i === 2) && v.includes(st)),
  );
}
const SAFE = new Set(
  (
    "api key keys token tokens auth oauth oauth2 account accounts credential credentials bot service prod production test staging dev main backup new old " +
    "read only read-only write readonly the a an for of and to my our client clients agency admin user app webhook header basic bearer refresh access " +
    "v1 v2 v3 live demo shared team company default custom personal work site store shop email mail crm erp cms db database check verify validate refresh rotate renew get set send fetch sync update create delete list handle store load save run call use find lookup parse build add remove generate request exchange issue approve reset manage monitor expiry expire expired status " +
    SERVICE_RULES.map((r) => r[1].toLowerCase()).join(" ")
  ).split(/\s+/),
);
function safeWord(tok) {
  const w = tok.replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, "");
  if (!w) return true;
  const l = w.toLowerCase();
  return (
    SAFE.has(l) ||
    /^[A-Z]{2,6}[0-9]?$/.test(w) ||
    /^v?\d{1,2}$/.test(w) ||
    l.split(/[-_]/).every((p) => SAFE.has(p))
  );
}

/**
 * Sanitise a user-written string. kind: 'name' (default), 'note', 'id' (machine identifiers: no keyword rule).
 * counters.names is incremented when anything was replaced.
 */
function sanitizeText(input, opts = {}) {
  const maxLen = opts.maxLen || 160;
  let s = normalise(input);
  if (!s) return "";
  const before = s;
  for (const [, re] of VALUE_PATTERNS) {
    re.lastIndex = 0;
    s = s.replace(re, "[redacted]");
  }
  s = s.replace(
    /\b[a-z][a-z0-9+.-]{1,10}:\/\/[^\s/:@]+:[^\s/@]+@/gi,
    "[redacted]",
  );
  const tokens = s.split(" ");
  const n = tokens.length;
  const mark = new Array(n).fill(false);
  const idMode = opts.kind === "id";
  const singles = tokens.filter((t) => t.length === 1).length;
  if (
    !idMode &&
    singles >= 3 &&
    STEMS.some((st) => st.length >= 4 && fold(tokens.join("")).includes(st))
  ) {
    if (opts.counters) opts.counters.names++;
    return "[redacted]";
  }
  for (let i = 0; i < n; i++) {
    const t = tokens[i];
    if (!t) continue;
    if (redactedRe.test(t)) mark[i] = true;
    else if (!idMode && hasStem(t)) {
      const lo = Math.max(0, i - 3);
      const hi = Math.min(n - 1, i + 8);
      // "CRM API key", "Gmail OAuth": a weak stem among plainly harmless words is a label, not a secret
      let harmless = weakStemOnly(t) && /^[A-Za-z0-9_-]+$/.test(t);
      for (let j = lo; harmless && j <= hi; j++) {
        if (j !== i && (!safeWord(tokens[j]) || tokenSuspicious(tokens[j])))
          harmless = false;
      }
      if (!harmless) for (let j = lo; j <= hi; j++) mark[j] = true;
    } else if (tokenSuspicious(t, 0, idMode)) mark[i] = true;
  }
  const out = [];
  for (let i = 0; i < n; i++) {
    if (mark[i]) {
      if (out[out.length - 1] !== "[redacted]") out.push("[redacted]");
    } else out.push(tokens[i]);
  }
  let res = out.join(" ");
  if (res !== before && opts.counters) opts.counters.names++;
  if (res.length > maxLen) res = res.slice(0, maxLen - 1) + "…";
  return res;
}

/**
 * Machine identifiers (node types, credential types, env var and variable names, hostnames).
 * Strict character set; anything else becomes "custom".
 */
function sanitizeIdent(input, opts = {}) {
  const raw = String(input == null ? "" : input);
  const bad = () => {
    if (opts.counters) opts.counters.names++;
    return "custom";
  };
  if (!/^[A-Za-z0-9_.@/$-]{1,100}$/.test(raw)) return bad();
  if (tokenSuspicious(raw, 0, true)) return bad();
  const f = fold(raw);
  const strong = STEMS.filter((s) => !WEAK.includes(s));
  if (
    /\d/.test(raw) &&
    [f, leet(f), f.split("").reverse().join("")].some((v) =>
      strong.some((st) => v.includes(st)),
    )
  )
    return bad();
  for (const [, re] of VALUE_PATTERNS) {
    re.lastIndex = 0;
    if (re.test(raw)) return bad();
  }
  return raw;
}

module.exports = {
  sanitizeIdent,
  normalise,
  fold,
  sanitizeText,
  tokenSuspicious,
  hasStem,
  STEMS,
};
