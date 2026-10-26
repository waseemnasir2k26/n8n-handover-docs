"use strict";
// ONE rule for "the token after a credential label is the credential", shared by the name policy
// (src/policy.js) and the final gate (src/gate.js). The words and their strength live in src/labels.js.
//   strong (password, pass, pwd, pw, passphrase, passcode, pin, secret ...): label + separator
//     (: = is) + ANY non-empty token -> that token is the value.
//   weak (credential(s), token, api key, auth, login, key, access ...): with ":" a VALUE-SHAPED token is
//     the value (a digit, a symbol, a known key shape, a long high-entropy run), and so is ONE plain word
//     that ends the name ("Token: Zebra"); two or more plain words are a name ("Token: refresh job").
//     With "=" ANY token is the value ("api key = tangerine", "token=abc").
//   label phrase: up to three words immediately before the separator. The phrase is strong when ANY of
//     its words is strong ("Secret Key: tangerine", "Admin Password: tangerine", "Door PIN: 4821").
//   fold(): diacritics, combining marks and look-alike letters are folded BEFORE any label matching
//     ("Passwörd", "Pásswórd", "Sécret" are the labels password and secret).
//   1.0.3 (fail closed, the whole remainder): every token after the separator is checked with safeWord().
//     A name keeps the remainder only if EVERY token is a safe word; any other token makes the whole remainder
//     the value ("Password - Slack abc123xyz", "Token - Sheet Zx9Kq2", "Secret: Slack 7f3a9b2c"). Reporting
//     periods (Q1-Q4, H1-H2, FY26) count as safe words ("Key Results: Q3 Growth").
//   dash (" - ", standalone token): strong + dash + ONE token at the end of the name -> the token is the
//     value ("Secret - tangerine"); strong + dash + two or more safe words -> a name ("Password - Reset Flow").
//     weak + dash + safe words -> a name ("Credentials - Slack").
//   weak + ":" + ONE safe token at the end of the name -> the value ("Token: Zebra", "Access Token: zebra");
//     weak + ":" + two or more safe words -> a name ("Token: refresh job").
//   ALLOW_PHRASES: label words inside these phrases are not labels ("Secret Santa", "Key Accounts").
//     With ":", "=" or a dash and ONE token ending the name, that token is a weak-label value
//     ("Key Accounts: tangerine", "Key Accounts - tangerine"); two or more plain words stay a name.
//   1.0.2 dash allow-list (fail closed): after a DASH, ONE token that ends the name is kept as a name only
//     if it is in KEPT_NOUNS or is an n8n node type name in the workflow (setNodeTypeNames). Any other single
//     token is the value ("Key Accounts - Tangerine", "Password - Zebra"; "PIN Code Generator - Sheet" stays).
//     ":" and "=" have no allow-list ("Password: reset" is a value).
// labelledValue() is the one decision for those rules; isLabelledValue() stays for attached / "is" forms.

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

// Matching fold: NFKD + combining marks removed (Passwörd -> Password), lower-cased, look-alikes -> Latin.
function fold(s) {
  let out = "";
  for (const ch of String(s)
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .toLowerCase())
    out += CONFUSABLES[ch] || ch;
  return out;
}

const KEY_PREFIX =
  /^(?:sk|pk|rk|ghp|gho|ghs|ghu|github_pat|glpat|xox[abposr]|hf|ya29)[-_][A-Za-z0-9]/;
const KEY_GLUED = /^(?:AKIA|ASIA|AIza|eyJ)[A-Za-z0-9_-]{8,}/;
const HEX_RUN = /[0-9a-fA-F]{16,}/;
const SYMBOL = /[@#$%^&*+=~|\!?]/;
const EDGE_OPEN = /^["'`([{<“‘]+/;
const EDGE_CLOSE = /["'`)\]}>”’,;:.!?…]+$/;

function entropy(s) {
  const f = new Map();
  for (const c of s) f.set(c, (f.get(c) || 0) + 1);
  let h = 0;
  for (const k of f.values()) h -= (k / s.length) * Math.log2(k / s.length);
  return h;
}

/** Does this token look like a value on its own (a digit, a symbol, a known key shape, high entropy)? */
function valueShaped(token) {
  const c = String(token == null ? "" : token)
    .replace(EDGE_OPEN, "")
    .replace(EDGE_CLOSE, "");
  if (!/[\p{L}\p{N}]/u.test(c)) return false;
  if (KEY_PREFIX.test(c) || KEY_GLUED.test(c) || HEX_RUN.test(c)) return true;
  if (/\p{N}/u.test(c) || SYMBOL.test(c)) return true;
  return [...c].length >= 20 && entropy(c) >= 4.2;
}

// Phrases whose words are never a credential label ("Secret Santa draw", "Key Results: Q4 review").
// With ":" or "=" and ONE token ending the name, that token is the value ("Key Accounts: tangerine").
const ALLOW_PHRASES = [
  ["secret", "santa"],
  ["secret", "sauce"],
  ["key", "accounts"],
  ["key", "results"],
  ["key", "performance", "indicators"],
  ["pin", "code", "generator"],
];

/** The words with every allow-listed phrase removed (matched case- and accent-insensitively). */
function stripAllowed(words) {
  const f = words.map((w) => fold(w).replace(/[^\p{L}\p{N}]/gu, ""));
  const keep = words.map(() => true);
  for (const phrase of ALLOW_PHRASES)
    for (let i = 0; i + phrase.length <= f.length; i++)
      if (phrase.every((w, k) => f[i + k] === w))
        for (let k = 0; k < phrase.length; k++) keep[i + k] = false;
  return words.filter((_, i) => keep[i]);
}

/** A word of letters only that is not value-shaped: an ordinary name word ("Zebra", "refresh"). */
function plainWord(token) {
  const c = String(token == null ? "" : token)
    .replace(EDGE_OPEN, "")
    .replace(EDGE_CLOSE, "");
  return /^\p{L}[\p{L}'’-]*$/u.test(c) && !valueShaped(c);
}

// Single-token nouns that may follow a label after a DASH and still be a name ("PIN Code Generator - Sheet",
// "Secret Sauce - Recipe", "Credentials - Slack"). Everything else after a dash is the value (fail closed).
// Not used after ":" or "=": "Password: reset" is a value.
const KEPT_NOUNS = new Set(
  [
    "sheet",
    "sheets",
    "recipe",
    "flow",
    "workflow",
    "generator",
    "report",
    "reports",
    "sync",
    "email",
    "emails",
    "slack",
    "gmail",
    "notion",
    "airtable",
    "webhook",
    "trigger",
    "reset",
    "rotation",
    "manager",
    "vault",
    "setup",
    "config",
    "docs",
    "template",
    "backup",
    "check",
    "refresh",
    "renew",
    "list",
    "form",
    "api",
    "crm",
    "hubspot",
    "stripe",
    "shopify",
    "drive",
    "calendar",
    "telegram",
    "discord",
    "twilio",
    "openai",
  ].map((w) => fold(w)),
);
// n8n node type names seen in the workflow JSON being rendered (set by generate()), folded, letters only.
let NODE_TYPE_NAMES = new Set();
const compact = (s) => fold(s).replace(/[^\p{L}\p{N}]/gu, "");

/** Replace the node-type names used by the keep-list. "n8n-nodes-base.googleSheets" -> "googlesheets". */
function setNodeTypeNames(types) {
  NODE_TYPE_NAMES = new Set();
  for (const t of types || []) {
    if (typeof t !== "string") continue;
    const k = compact(t.split(".").pop());
    if (k) NODE_TYPE_NAMES.add(k);
  }
}

/** A single token that may stay a name after a dash: an allow-listed noun or an n8n node type name. */
function isKeptNoun(token) {
  const c = String(token == null ? "" : token)
    .replace(EDGE_OPEN, "")
    .replace(EDGE_CLOSE, "");
  const k = compact(c);
  return k !== "" && (KEPT_NOUNS.has(k) || NODE_TYPE_NAMES.has(k));
}

// 1.0.3: a "safe word" is the only kind of token a name may carry after a label. Letters only (an optional
// ' or - inside), at most 12 letters, no capital after the first letter; an allow-listed noun always passes.
// Any digit, other symbol, mixed case (aBc, camelCase, GoogleSheets unless it is a kept noun) or longer
// word makes the token a possible value, so the whole remainder of the name is treated as the value.
const SAFE_WORD_MAX = 12;
function safeWord(token) {
  const c = String(token == null ? "" : token)
    .replace(EDGE_OPEN, "")
    .replace(EDGE_CLOSE, "");
  if (DASH_TOKENS.has(c)) return true;
  // reporting periods are names, not values ("Key Results: Q3 Growth", "Key Results - Q4 review")
  if (/^(?:Q[1-4]|H[12]|FY\d{2})$/i.test(c)) return true;
  if (!/^\p{L}[\p{L}'’-]*$/u.test(c)) return false;
  if (isKeptNoun(c)) return true;
  return [...c].length <= SAFE_WORD_MAX && !/\p{Lu}/u.test(c.slice(1));
}

/**
 * The shared decision for a token after a label phrase and a separator.
 *   sep: ":" | "=" | "-" (a dash) | null (any other marker: falls back to isLabelledValue).
 *   next: the token after this one in the same segment, or null when the name ends here.
 *   rest: every token after this one in the same segment (default [next]). ALL of them are checked (1.0.3).
 * True when the token is the credential value; the caller then redacts the token and its rest.
 */
function labelledValue(kind, sep, token, next, rest) {
  const c = String(token == null ? "" : token);
  if (!/[\p{L}\p{N}]/u.test(c) || /^\?\[?redacted/i.test(c)) return false;
  if (sep === "=") return true;
  if (sep !== ":" && sep !== "-") return isLabelledValue(kind, c);
  const tail = [c, ...(rest !== undefined ? rest : next == null ? [] : [next])];
  if (kind === "strong") {
    if (sep === ":") return true;
    // dash: any token that is not a safe word makes the remainder a value
    if (!tail.every(safeWord)) return true;
    // safe words only: a name, except ONE token that is not an allow-listed noun ("Password - Zebra")
    return tail.length === 1 && !isKeptNoun(c);
  }
  if (kind !== "weak") return false;
  // a value-shaped token (digit, symbol, key shape, long random run) is never a safe word, so it is a value here
  if (!tail.every(safeWord)) return true;
  if (sep === "-") return false; // weak + dash + safe words: a name ("Credentials - Slack Alerts")
  // weak + ":": one safe word that ends the name is the value; two or more safe words are a name
  return tail.length === 1;
}

/**
 * kind: "strong" | "weak". token: the first token after the label and its separator.
 * True when that token is the credential value under the strong/weak rule.
 */
function isLabelledValue(kind, token) {
  const c = String(token == null ? "" : token);
  if (!/[\p{L}\p{N}]/u.test(c) || /^\\?\[?redacted/i.test(c)) return false;
  if (kind === "strong") return true;
  if (kind === "weak") return valueShaped(c);
  return false;
}

// ---- label phrases before a separator ----
const PHRASE_MAX = 3;
const DASH_TOKENS = new Set(["-", "–", "—"]);
const WORD_TOKEN = /^[\p{L}\p{N}_'’-]+$/u;
const EDGE_WORD = /^["'`([{<“‘]+|["'`)\]}>”’,.!?…]+$/g;
const isWordToken = (t) => WORD_TOKEN.test(String(t).replace(EDGE_WORD, ""));

// The word that follows a value, cut at the first field mark (a CSV or table quote, comma, bracket):
// `Backup","Slack"` is the word Backup. Null when the name ends here (a segment break, nothing, `""`).
const FIELD_END = /["'`,;|<>()[\]{}“”‘’]/u;
function nextToken(tokens, idx, breaks = new Set()) {
  if (idx >= tokens.length || breaks.has(idx)) return null;
  const c = String(tokens[idx]).replace(/^["'`([“‘]+/u, "");
  const cut = c.search(FIELD_END);
  const piece = cut >= 0 ? c.slice(0, cut) : c;
  return piece === "" ? null : piece;
}

/**
 * The separator at tokens[i] and the label phrase (up to three words immediately before it).
 *   "Key:" -> phrase = words before, plus "Key"; ":" or "=" alone -> phrase = words before it;
 *   "Key:tangerine" / "token=abc" -> the value is attached (attached: true, value = "tangerine").
 *   a standalone dash ("-", en or em dash) is a separator: "Secret - tangerine".
 * `breaks` (optional Set) marks token indexes that start a new segment (a table cell, a tag): the
 * name ends there. Returns { sep, base, words, value, valueIdx, attached, next } or null.
 * value is the token (or attached text) after the separator, null when there is none; next is the
 * token after the value in the same segment, or null.
 */
/**
 * The tokens from idx to the end of the segment (a break or a name end), each as its text (nextToken cut).
 * Whitespace-only tokens are skipped. Used for the remainder check and for redaction (1.0.3).
 */
function tailOf(tokens, idx, breaks = new Set()) {
  const out = [];
  for (let j = idx; j < tokens.length; j++) {
    if (breaks.has(j)) break;
    if (String(tokens[j]).trim() === "") continue;
    const text = nextToken(tokens, j, breaks);
    if (text === null) break;
    out.push({ idx: j, text });
  }
  return out;
}

function separatorAt(tokens, i, breaks = new Set()) {
  const t = String(tokens[i]);
  let sep;
  let base = null;
  let value = null;
  if (t === ":" || t === "=") sep = t;
  else if (DASH_TOKENS.has(t)) sep = "-";
  else {
    const m = /^(.+?)([:=])(.*)$/u.exec(t);
    if (!m || !isWordToken(m[1]) || t.includes("://")) return null;
    base = m[1];
    sep = m[2];
    if (m[3] !== "") value = m[3];
  }
  const room = PHRASE_MAX - (base === null ? 0 : 1);
  const before = [];
  for (let j = i - 1; j >= 0 && before.length < room; j--) {
    if (!isWordToken(tokens[j]) || breaks.has(j + 1)) break;
    before.unshift(String(tokens[j]).replace(EDGE_WORD, ""));
  }
  const raw = base === null ? before : [...before, base];
  const words = stripAllowed(raw);
  const attached = value !== null;
  let valueIdx = i;
  if (!attached) {
    valueIdx = i + 1;
    while (valueIdx < tokens.length && String(tokens[valueIdx]).trim() === "")
      valueIdx++;
    if (valueIdx < tokens.length) value = String(tokens[valueIdx]);
  }
  // every token after the value in this segment: the whole remainder is checked, and redacted when it is a value
  const tail = attached ? [] : tailOf(tokens, valueIdx, breaks);
  const after = attached ? tailOf(tokens, i + 1, breaks) : tail.slice(1);
  const next = after.length ? after[0].text : null;
  const rest = after.map((x) => x.text);
  // An allow-listed phrase is never a label by itself. With only that phrase before the separator, the
  // value is a weak label for the remainder, applied as ":" ("Key Accounts: tangerine" is a value,
  // "Key Accounts: weekly sync" a name, "Key Accounts - Tangerine abc123" a value). A dash followed by ONE
  // allow-listed noun or n8n node type stays a name ("PIN Code Generator - Sheet").
  const allowedOnly =
    raw.length > words.length &&
    words.length === 0 &&
    (sep === ":" || sep === "=" || sep === "-") &&
    value !== null;
  if (!words.length && !allowedOnly) return null;
  if (allowedOnly && sep === "-" && rest.length === 0 && isKeptNoun(value))
    return null;
  return {
    sep: allowedOnly ? ":" : sep,
    base,
    words,
    value,
    valueIdx,
    attached,
    next,
    rest,
    tail,
    // the value is a run of unsafe tokens: the whole remainder goes ("Password - Slack abc123xyz")
    unsafe: !tail.every((t) => safeWord(t.text)),
    allowedSingle: allowedOnly,
  };
}

/** The kind a separator applies to the token after it (see separatorKind); allowedSingle is a weak label. */
function separatorKindAt(sep, kindOfWord) {
  const phraseKind =
    phraseKindOf(sep.words, kindOfWord) || (sep.allowedSingle ? "weak" : null);
  return separatorKind(sep.sep, phraseKind);
}

/** Kind of a label phrase: "strong" if any word is strong, else "weak" if any word is weak, else null. */
function phraseKindOf(words, kindOfWord) {
  let best = null;
  for (const w of words) {
    const k = kindOfWord(w);
    if (k === "strong") return "strong";
    if (k) best = "weak";
  }
  return best;
}

/**
 * The kind a separator applies to the token after it. "=" is an assignment: any label kind takes any
 * token, so it returns "strong". ":" keeps the phrase's strong/weak kind. No label, no kind.
 */
function separatorKind(sep, phraseKind) {
  if (!phraseKind) return null;
  return sep === "=" ? "strong" : phraseKind;
}

module.exports = {
  isLabelledValue,
  valueShaped,
  fold,
  separatorAt,
  separatorKindAt,
  phraseKindOf,
  separatorKind,
  isWordToken,
  labelledValue,
  nextToken,
  tailOf,
  safeWord,
  stripAllowed,
  plainWord,
  isKeptNoun,
  setNodeTypeNames,
};
