"use strict";
// NAME POLICY. Every user-written string that reaches the pack (workflow, node, tag, credential and
// sub-workflow names, and notes when --include-notes is on) is normalised first, then only the
// suspicious VALUE is replaced with [redacted]. Credential words (English plus es, fr, de, pt, tr,
// id, ru, ar, hi, ur, ja, ko, zh) are matched as whole tokens, never as substrings ("Passenger",
// "Keyword", "Credit" are ordinary words), and a credential word alone is not a secret:
// "Send Token Report" stays, "token: ghp_..." becomes "token: [redacted]".
const { VALUE_PATTERNS } = require("./secrets");
const { STRONG, WEAK, CJK_LABELS, CODE_WORDS } = require("./labels");

const CONNECTORS = new Set([
  ":",
  "=",
  "=>",
  "->",
  "is",
  "are",
  "was",
  "equals",
  "-",
  "–",
  "—",
  "/",
  "→",
  "for",
  "the",
  "of",
  "to",
  "a",
  "an",
  "my",
  "your",
  "our",
  "是",
  "为",
]);
const MARKERS = new Set([
  ":",
  "=",
  "=>",
  "->",
  "is",
  "are",
  "was",
  "equals",
  "→",
  "是",
  "为",
]);

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

// Unicode-aware character classes: letters/marks/numbers in any script
const L = "\\p{L}\\p{M}";
const EDGE = new RegExp(`^[^${L}\\p{N}]+|[^${L}\\p{N}]+$`, "gu");
const HAS_DIGIT = /\p{N}/u;
const HAS_LETTER = /\p{L}/u;
const SYMBOL = /[!@$%^&*+~]/;

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
// label sets folded the same way tokens are (look-alike letters become Latin), so matching is symmetric
const foldLabel = (w) => fold(w).replace(/[-_\s]/g, "");
const STRONG_F = new Set([...STRONG].map(foldLabel));
const WEAK_F = new Set([...WEAK].map(foldLabel));

function leet(s) {
  let out = "";
  for (const ch of s) out += LEET[ch] || ch;
  return out;
}

function entropy(s) {
  const f = new Map();
  let n = 0;
  for (const c of s) {
    f.set(c, (f.get(c) || 0) + 1);
    n++;
  }
  let h = 0;
  for (const k of f.values()) h -= (k / n) * Math.log2(k / n);
  return h;
}

// Words, numbers and short codes joined by - . _ / (lg-04, Customer-Support-Agent-2025, se-11c, v2-final)
const slugLike = (t) =>
  /^[\p{L}\p{N}]+([-._/][\p{L}\p{N}]+)+$/u.test(t) &&
  t
    .split(/[-._/]/)
    .every(
      (p) =>
        /^\p{L}{1,18}$/u.test(p) ||
        /^\p{N}{1,4}$/u.test(p) ||
        /^[\p{L}\p{N}]{1,4}$/u.test(p),
    );

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

const countDigits = (t) => (t.match(/\p{N}/gu) || []).length;
const cpLen = (t) => [...t].length;

/** Does this single token look like a secret value on its own? Independent of credential words. */
function tokenSuspicious(tok, depth = 0, idMode = false) {
  const t = tok.replace(/^[^\p{L}\p{N}]+/u, "").replace(/[.,;:)\]}>'"]+$/, "");
  if (!t) return false;
  const len = cpLen(t);
  const letters = HAS_LETTER.test(t);
  const digits = countDigits(t);
  const upper = /\p{Lu}/u.test(t);
  const lower = /\p{Ll}/u.test(t);
  const symbol = SYMBOL.test(t);
  if (idMode) {
    // machine identifiers (camelCase types like googleSheetsOAuth2Api are normal)
    if (/[0-9a-fA-F]{16,}/.test(t)) return true;
    if (len >= 16 && digits >= 3 && letters && !slugLike(t)) return true;
    if (len >= 8 && letters && digits >= 1 && symbol) return true;
    if (len >= 20 && entropy(t) >= 4.0 && digits >= 2) return true;
    const d = depth < 2 ? b64Decode(t) : null;
    return !!(d && (/\d/.test(d) || d.includes(":")));
  }
  if (/[0-9a-fA-F]{16,}/.test(t)) return true;
  if (!slugLike(t)) {
    if (len >= 12 && letters && digits >= 2) return true;
    if (len >= 8 && letters && digits >= 1 && symbol) return true;
    if (len >= 10 && upper && lower && digits >= 2) return true;
    if (
      len >= 16 &&
      entropy(t) >= 3.5 &&
      (digits >= 1 || (upper && lower)) &&
      !/^\p{L}+$/u.test(t)
    )
      return true;
  }
  if (depth < 2) {
    const d = b64Decode(t);
    if (
      d &&
      (kwKind(d.split(/[^A-Za-z0-9_]+/)[0]) || /\d/.test(d) || d.includes(":"))
    )
      return true;
  }
  return false;
}

/** 'strong' | 'weak' | null: is this whole token a credential word (any supported language)? */
function kwKind(tok) {
  const c = fold(String(tok).replace(EDGE, "")).replace(/[-_\s]/g, "");
  if (!c || cpLen(c) > 24) return null;
  const variants = [c];
  if (/^[a-z0-9@$!]+$/.test(c)) {
    variants.push(leet(c));
    if (c.length >= 5) variants.push(c.split("").reverse().join(""));
  }
  for (const v of variants) if (STRONG_F.has(v)) return "strong";
  for (const v of variants) if (WEAK_F.has(v)) return "weak";
  return null;
}

// a value worth redacting when it follows a credential word
function valueLike(tok) {
  const c = tok.replace(/^["'`([{]+|["'`)\]},;.]+$/g, "");
  if (cpLen(c) < 6 || /^\[?redacted\]?$/i.test(c)) return false;
  if (/^v?\d+([.\-/]\d+)*$/i.test(c) || /^\d{4}-\d{2}-\d{2}/.test(c))
    return false;
  if (tokenSuspicious(c)) return true;
  return (HAS_DIGIT.test(c) || SYMBOL.test(c)) && !slugLike(c);
}
const hasDigitOrSymbol = (t) => HAS_DIGIT.test(t) || SYMBOL.test(t);

const redactedRe = /\[redacted\]/;

// "s e c r e t :" -> "secret :" when the single letters spell a credential word
function joinSpelled(tokens) {
  const out = [];
  for (let i = 0; i < tokens.length; i++) {
    let j = i;
    while (
      j < tokens.length &&
      j - i < 14 &&
      /^[\p{L}\p{N}][:=]?$/u.test(tokens[j])
    )
      j++;
    if (j - i >= 4) {
      const letters = tokens
        .slice(i, j)
        .map((t) => t.replace(/[:=]$/, ""))
        .join("");
      if (kwKind(letters)) {
        out.push(
          letters +
            (/[:=]$/.test(tokens[j - 1]) ? tokens[j - 1].slice(-1) : ""),
        );
        i = j - 1;
        continue;
      }
    }
    out.push(tokens[i]);
  }
  return out;
}

const isCjk = (t) => /[぀-ヿ㐀-鿿가-힯]/.test(t);

/**
 * Sanitise a user-written string. opts.kind: 'name' (default) or 'note' (stricter, used for sticky notes).
 * counters.names counts distinct strings in which something was actually redacted.
 */
function sanitizeText(input, opts = {}) {
  const maxLen = opts.maxLen || 160;
  const noteMode = opts.kind === "note";
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
  s = s.replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[redacted]");
  const tokens = joinSpelled(s.split(" "));
  const n = tokens.length;
  const mark = new Array(n).fill(false);
  const partial = new Map();

  // a whole name that is one short mixed token ("hunter22", "k9x!2q") is a password, not a name
  if (n === 1 && !noteMode) {
    const t = tokens[0];
    const len = cpLen(t);
    if (
      len >= 5 &&
      len <= 12 &&
      HAS_LETTER.test(t) &&
      !slugLike(t) &&
      !redactedRe.test(t) &&
      (countDigits(t) >= 2 || (countDigits(t) >= 1 && SYMBOL.test(t)))
    ) {
      mark[0] = true;
    }
  }

  // runs of spaced digits ("4 8 1 5 9 2") and grouped numbers (cards, IBANs)
  for (let i = 0; i < n; ) {
    let j = i;
    while (j < n && /^\p{Nd}$/u.test(tokens[j])) j++;
    if (j - i >= 5) for (let q = i; q < j; q++) mark[q] = true;
    let g = i;
    while (g < n && /^\d{3,4}$/.test(tokens[g])) g++;
    if (g - i >= 3) for (let q = i; q < g; q++) mark[q] = true;
    i = Math.max(i + 1, j, g);
  }

  for (let i = 0; i < n; i++) {
    const t = tokens[i];
    if (!t) continue;
    if (redactedRe.test(t)) {
      mark[i] = true;
      continue;
    }
    // CJK labels live inside tokens: 密码是蓝天白云88, パスワード:さくら77
    if (isCjk(t)) {
      const lab = CJK_LABELS.find((l) => t.includes(l));
      if (lab) {
        const idx = t.indexOf(lab) + lab.length;
        const rest = t.slice(idx);
        const explicit = /^[:=是为]/.test(rest);
        const body = rest.replace(/^[:=是为\s]+/, "");
        if (
          body &&
          (explicit || HAS_DIGIT.test(body) || /[A-Za-z]/.test(body))
        ) {
          partial.set(
            i,
            t.slice(0, idx) +
              (rest.match(/^[:=是为]+/) || [""])[0] +
              "[redacted]",
          );
          continue;
        }
      }
    }
    // attached assignment: api_key=VALUE, password:VALUE, "token":"VALUE"
    const m = /^["'`]?([^:=\s"'`]{1,40})["'`]?([:=])["'`]?(.+)$/u.exec(t);
    if (m && !t.includes("://") && kwKind(m[1])) {
      partial.set(i, `${m[1]}${m[2]}[redacted]`);
      continue;
    }
    if (
      tokenSuspicious(t) ||
      // notes are free text: any word welded to a digit and 8+ characters long is treated as a value
      (noteMode &&
        cpLen(t) >= 8 &&
        HAS_LETTER.test(t) &&
        HAS_DIGIT.test(t) &&
        !slugLike(t) &&
        !/^\d{1,2}[:.]\d{2}/.test(t) &&
        !/^[\p{Sc}\d.,%/-]+$/u.test(t))
    ) {
      mark[i] = true;
      continue;
    }
    // credential word: one token, or up to three joined (kata sandi, mot de passe, كلمة السر)
    let k = kwKind(t);
    let end = i;
    if (!k) {
      for (let w = 2; w <= 3 && i + w <= n && !k; w++) {
        const parts = tokens.slice(i, i + w);
        if (
          parts.every(
            (p) => cpLen(p.replace(EDGE, "")) <= 12 && !HAS_DIGIT.test(p),
          )
        ) {
          const kk = kwKind(parts.join(""));
          if (kk === "strong") {
            k = kk;
            end = i + w - 1;
          }
        }
      }
    }
    if (!k) {
      // code / pin / safe / door / alarm followed by a spaced digit run is handled above; also a bare label here
      if (CODE_WORDS.has(fold(t.replace(EDGE, "")))) {
        for (let q = i + 1; q < Math.min(n, i + 9); q++)
          if (/^\p{Nd}$/u.test(tokens[q])) mark[q] = true;
      }
      continue;
    }
    let explicit = /[:=]$/.test(tokens[end]);
    let j = end + 1;
    for (let steps = 0; j < n && steps < 3; steps++) {
      const low = tokens[j]
        .toLowerCase()
        .replace(/^[^\p{L}:=→\-–—/>]+|[^\p{L}:=→\-–—/>]+$/gu, "");
      if (!CONNECTORS.has(low)) break;
      if (MARKERS.has(low)) explicit = true;
      if (
        noteMode &&
        (low === "-" || low === "/" || low === "–" || low === "—")
      )
        explicit = true;
      j++;
    }
    if (
      !explicit &&
      k === "strong" &&
      !/^(pass|sk)$/.test(foldLabel(tokens[end]))
    ) {
      // "the password for the CRM is tangerine": an assignment a few words later
      for (let q = j; q < Math.min(n, end + 7); q++) {
        if (MARKERS.has(tokens[q].toLowerCase())) {
          explicit = true;
          j = q + 1;
          break;
        }
      }
    }
    if (j < n) {
      if (noteMode && k === "strong") {
        // notes are free text: after a password word take the next few words
        for (let q = j; q < Math.min(n, j + (explicit ? 4 : 2)); q++) {
          mark[q] = true;
          if (/[.;]$/.test(tokens[q])) break;
        }
        // table headers and lists put the value several cells later
        for (let q = j; q < Math.min(n, j + 10); q++)
          if (valueLike(tokens[q])) mark[q] = true;
      } else if (explicit && k === "strong" && !valueLike(tokens[j])) {
        // "password is correct horse battery": a plain-word phrase assigned to a password word
        for (let q = j; q < Math.min(n, j + 4); q++) {
          mark[q] = true;
          if (/[.;]$/.test(tokens[q])) break;
        }
      } else if (noteMode && explicit && k === "weak") {
        for (let q = j; q < Math.min(n, j + 3); q++) {
          if (/^[-/–—]$/.test(tokens[q])) continue;
          mark[q] = true;
        }
      } else if (valueLike(tokens[j])) {
        mark[j] = true;
        if (
          j + 1 < n &&
          /^[^\s]{1,10}$/.test(tokens[j + 1]) &&
          /[\p{N}!@$%^&*+~]/u.test(tokens[j + 1]) &&
          !redactedRe.test(tokens[j + 1])
        )
          mark[j + 1] = true;
      } else if (
        explicit &&
        hasDigitOrSymbol(tokens[j]) &&
        cpLen(tokens[j]) >= 3
      ) {
        mark[j] = true;
      }
    }
    if (k === "strong") {
      for (let b = Math.max(0, i - 4); b < i; b++)
        if (
          valueLike(tokens[b]) ||
          (HAS_DIGIT.test(tokens[b]) && cpLen(tokens[b]) >= 6)
        )
          mark[b] = true;
    }
    i = Math.max(i, end);
  }
  const out = [];
  for (let i = 0; i < n; i++) {
    if (partial.has(i)) out.push(partial.get(i));
    else if (mark[i]) {
      if (out[out.length - 1] !== "[redacted]") out.push("[redacted]");
    } else out.push(tokens[i]);
  }
  let res = out.join(" ");
  if (res !== before && opts.counters) {
    const c = opts.counters;
    if (!c.seen) c.seen = new Set();
    c.seen.add(before);
    c.names = c.seen.size;
  }
  if (cpLen(res) > maxLen) res = [...res].slice(0, maxLen - 1).join("") + "…";
  return res;
}

const camelWords = (s) => s.match(/[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+/g) || [];

/**
 * Machine identifiers (node types, credential types, env var and variable names, connection types, hostnames).
 * Strict character set; anything else becomes "custom".
 */
function sanitizeIdent(input, opts = {}) {
  const raw = String(input == null ? "" : input);
  const bad = () => {
    if (opts.counters) {
      const c = opts.counters;
      if (!c.seen) c.seen = new Set();
      c.seen.add(raw);
      c.names = c.seen.size;
    }
    return "custom";
  };
  if (!/^[A-Za-z0-9_.@/$-]{1,100}$/.test(raw)) return bad();
  if (raw.split(/[@/.]/).some((seg) => seg && tokenSuspicious(seg, 0, true)))
    return bad();
  for (const [, re] of VALUE_PATTERNS) {
    re.lastIndex = 0;
    if (re.test(raw)) return bad();
  }
  // a credential word welded to digits (pass__Zq8wRt5Yu, passcode482910)
  if (
    /\d/.test(raw) &&
    camelWords(raw.replace(/[_.\-/@$]/g, " ")).some(
      (w) => kwKind(w) === "strong",
    )
  )
    return bad();
  return raw;
}

module.exports = {
  normalise,
  fold,
  sanitizeText,
  sanitizeIdent,
  tokenSuspicious,
  kwKind,
  valueLike,
};
