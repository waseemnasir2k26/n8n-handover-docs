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
//   dash (" - ", standalone token): strong + dash + ONE token at the end of the name -> the token is the
//     value ("Secret - tangerine"); strong + dash + two or more plain words -> a name ("Password - Reset Flow").
//     weak + dash + any plain word -> a name ("Credentials - Slack"); a value-shaped token -> the value.
//   weak + ":" + ONE plain token at the end of the name -> the value ("Token: Zebra", "Access Token: zebra");
//     weak + ":" + two or more plain words -> a name ("Token: refresh job").
//   ALLOW_PHRASES: label words inside these phrases are not labels ("Secret Santa", "Key Accounts").
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
  for (const ch of String(s).normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase())
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

// Phrases whose words are never a credential label ("Secret Santa: Alice", "Key Accounts - Q3").
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

/**
 * The shared decision for a token after a label phrase and a separator.
 *   sep: ":" | "=" | "-" (a dash) | null (any other marker: falls back to isLabelledValue).
 *   next: the token after this one in the same segment, or null when the name ends here.
 * True when the token is the credential value.
 */
function labelledValue(kind, sep, token, next) {
  const c = String(token == null ? "" : token);
  if (!/[\p{L}\p{N}]/u.test(c) || /^\?\[?redacted/i.test(c)) return false;
  if (sep === "=") return true;
  if (sep !== ":" && sep !== "-") return isLabelledValue(kind, c);
  if (kind === "strong") {
    if (sep === ":") return true;
    // dash: two or more plain words are a name
    return !(plainWord(c) && next != null && plainWord(next));
  }
  if (kind !== "weak") return false;
  if (valueShaped(c)) return true;
  if (sep === "-") return false; // weak + dash + plain words: a name
  // weak + ":": one plain word that ends the name is the value
  return next == null && plainWord(c);
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
  const words = stripAllowed(base === null ? before : [...before, base]);
  if (!words.length) return null;
  const attached = value !== null;
  if (!attached && i + 1 < tokens.length) value = String(tokens[i + 1]);
  const valueIdx = attached ? i : i + 1;
  const nextIdx = valueIdx + 1;
  const next = nextToken(tokens, nextIdx, breaks);
  return { sep, base, words, value, valueIdx, attached, next };
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
  phraseKindOf,
  separatorKind,
  isWordToken,
  labelledValue,
  nextToken,
  stripAllowed,
  plainWord,
};
