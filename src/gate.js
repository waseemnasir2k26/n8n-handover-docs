"use strict";
// INDEPENDENT final gate. Deliberately shares no logic with the scrubber (src/policy.js): it
// classifies every token of the finished output by Unicode character classes, length and entropy
// over code points, also after base64 / %-decoding, and looks for credential words (any supported
// language) followed by a value-looking token, spaced digit runs and grouped numbers. Reports
// file:line and a kind, never the value. When gitleaks is on PATH it is run as a second,
// third-party detector over the same files.
const cp = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  STRONG: STRONG_LABELS,
  ALL_LABELS,
  CJK_LABELS,
  CODE_WORDS,
  EMOJI_LABELS,
  PIN_LABELS,
  SUFFIX_LABELS,
  SPOKEN_DIGITS,
  NATO,
  inLabelSet,
} = require("./labels");
const { isLabelledValue } = require("./value-rule");

const LABEL_SET = new Set(ALL_LABELS);
const SPLIT = /[\s"'<>()[\]{},;|=:\\：]+/;
const EDGE = /^[^\p{L}\p{M}\p{N}]+|[^\p{L}\p{M}\p{N}]+$/gu;

function codePoints(s) {
  return [...s];
}

function shannon(s) {
  const m = new Map();
  const cps = codePoints(s);
  for (const c of cps) m.set(c, (m.get(c) || 0) + 1);
  let h = 0;
  for (const n of m.values()) h -= (n / cps.length) * Math.log2(n / cps.length);
  return h;
}

function classes(t) {
  return (
    (/\p{Ll}/u.test(t) ? 1 : 0) +
    (/\p{Lu}/u.test(t) ? 1 : 0) +
    (/\p{L}/u.test(t) && !/[\p{Ll}\p{Lu}]/u.test(t) ? 1 : 0) +
    (/\p{N}/u.test(t) ? 1 : 0) +
    (/[^\p{L}\p{N}]/u.test(t) ? 1 : 0)
  );
}

function isSlug(t) {
  // words, numbers and short codes joined by - . _ / (file names, anchors, Customer-Support-Agent-2025, lg-04)
  return (
    /^[\p{L}\p{N}]+([-._/][\p{L}\p{N}]+)+$/u.test(t) &&
    t
      .split(/[-._/]/)
      .every(
        (p) =>
          /^\p{L}{1,18}$/u.test(p) ||
          /^\p{N}{1,4}$/u.test(p) ||
          /^[\p{L}\p{N}]{1,4}$/u.test(p),
      )
  );
}

// file names and anchors the pack itself generates: safe-words + a 6-hex hash (flow-password-734a59.md)
function packName(t) {
  const m = /^#?(?:wf-)?(.+?)-h[0-9a-f]{6}(?:-\d+)?(?:\.md)?$/.exec(t);
  return !!m && (isSlug(m[1]) || /^\p{L}{1,18}\d{0,4}$/u.test(m[1]));
}

function valueLike(t) {
  if (packName(t.replace(/^[^\p{L}\p{N}#]+|[^\p{L}\p{N}]+$/gu, "")))
    return false;
  const c = t.replace(
    /^[^\p{L}\p{N}!@#$%^&*+~]+|[^\p{L}\p{N}!@#$%^&*+~]+$/gu,
    "",
  );
  if (codePoints(c).length < 6) return false;
  if (/^\[?redacted\]?$/i.test(c) || isSlug(c) || CRED_TYPE_ID.test(c))
    return false;
  return (/\p{N}/u.test(c) && /\p{L}/u.test(c)) || /[!@$%^&*+~]/.test(c);
}

function suspiciousToken(t, depth = 0) {
  const c = t
    .replace(/^[^\p{L}\p{N}]+/u, "")
    .replace(/[.,;)\]}>'"…_/-]+$/u, "");
  const len = codePoints(c).length;
  if (len < 8) return null;
  if (packName(c)) return null;
  const digits = (c.match(/\p{N}/gu) || []).length;
  const letters = /\p{L}/u.test(c);
  if (/[0-9a-fA-F]{16,}/.test(c)) return "hex run";
  if (!isSlug(c)) {
    if (len >= 20 && digits >= 2 && classes(c) >= 3 && shannon(c) >= 3.4)
      return "high-entropy token";
    if (len >= 12 && letters && digits >= 2) return "letters+digits token";
    if (len >= 8 && letters && digits >= 1 && /[!@$%^&*+~?]/.test(c))
      return "password-like token";
    if (len >= 10 && /\p{Ll}/u.test(c) && /\p{Lu}/u.test(c) && digits >= 2)
      return "mixed-case+digit token";
  }
  if (depth < 2) {
    if (/%[0-9a-fA-F]{2}/.test(c)) {
      try {
        const d = decodeURIComponent(c);
        const r =
          suspiciousToken(d, depth + 1) ||
          (d.split(SPLIT).some((x) => LABEL_SET.has(x.toLowerCase())) &&
          d.split(SPLIT).some(valueLike)
            ? "url-encoded credential"
            : null);
        if (r) return `url-decoded ${r}`;
      } catch {
        /* not decodable */
      }
    }
    if (/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(c)) {
      const buf = Buffer.from(
        c.replace(/-/g, "+").replace(/_/g, "/"),
        "base64",
      );
      let p = 0;
      for (const b of buf) if ((b >= 32 && b < 127) || b === 10) p++;
      if (buf.length >= 8 && p / buf.length >= 0.85) {
        const d = buf.toString("latin1");
        if (
          d.split(/[^A-Za-z]+/).some((x) => LABEL_SET.has(x.toLowerCase())) ||
          /\d/.test(d) ||
          d.includes(":") ||
          suspiciousToken(d, depth + 1)
        )
          return "base64-decoded content";
      }
    }
  }
  return null;
}

function decodeLine(raw) {
  return raw
    .normalize("NFKC")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/&#(\d{1,7});/g, (m, d) =>
      String.fromCodePoint(Math.min(+d, 0x10ffff)),
    )
    .replace(/#(\d{2,3});/g, (m, d) => String.fromCharCode(+d)) // Mermaid entities
    .replace(/\\([\\`*_[\]<>|~&#+\-=.!(){}])/g, "$1");
}

// ---- labels inside compounds (DB-Password, db_password, dbPassword, Login-PIN) ----
const GATE_LABELS = new Set([...LABEL_SET, ...PIN_LABELS]);
// A name after a credential label and a DASH: "Credentials - Slack." or a table cell "<td>Credentials - Slack</td>". A run of
// plain-letter words (<= 20 letters each) that ends at a sentence mark, quote, comma or markup boundary is prose, not a value.
// Any digit or symbol makes it a value. Colon and "=" values are never exempt: "password: tangerine" stays blocked.
const DASH_MARKS = new Set(["-", "–", "—"]);
const PLAIN_WORD = /^\p{L}{1,20}$/u;
const FIELD_END = /["'`,;|<>()[\]{}“”‘’]/u;
// the word up to the first field/markup mark, and whether the run ends there (quote, comma, bracket, sentence mark)
function plainPiece(t) {
  const c = t.replace(/^["'`([“‘]+/u, "");
  const cut = c.search(FIELD_END);
  const piece = cut >= 0 ? c.slice(0, cut) : c;
  const ends = cut >= 0 || /[.:!?…]$/u.test(piece);
  return { word: piece.replace(/[.,;:!?…]+$/u, ""), ends };
}
function plainRun(toks, start, breaks = new Set()) {
  if (start >= toks.length) return false;
  for (let j = start; j < toks.length; j++) {
    if (j > start && breaks.has(j)) return true; // a table cell or tag ended the value
    const { word, ends } = plainPiece(toks[j]);
    if (word === "" && ends && j > start) return true; // a bare quote or comma closes the run
    if (!PLAIN_WORD.test(word)) return false;
    if (ends) return true;
  }
  return true;
}
const MARK_TOKENS = new Set([
  ":",
  "=",
  "=>",
  "->",
  "\u2192",
  "is",
  "-",
  "\u2013",
  "\u2014",
  ":=",
]);
const SUFFIX_SET = SUFFIX_LABELS;
function gateWordsRaw(tok) {
  return tok
    .replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, "")
    .replace(/([\p{Ll}\p{N}])(\p{Lu})/gu, "$1 $2")
    .replace(/(\p{Lu})(\p{Lu}\p{Ll})/gu, "$1 $2")
    .split(/[-_.\s]+/u)
    .filter(Boolean);
}
function hasGlued(tok) {
  for (const w of gateWordsRaw(tok)) {
    const lw = w.toLowerCase();
    if (SUFFIX_SET.some((lab) => lw.length > lab.length && lw.endsWith(lab)))
      return true;
    if (/^[A-Z0-9]{4,}$/.test(w) && lw.endsWith("pin")) return true;
  }
  return false;
}
function gateWords(tok) {
  return tok
    .replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, "")
    .replace(/([\p{Ll}\p{N}])(\p{Lu})/gu, "$1 $2")
    .replace(/(\p{Lu})(\p{Lu}\p{Ll})/gu, "$1 $2")
    .split(/[-_.\s]+/u)
    .filter(Boolean)
    .map((w) => w.toLowerCase().normalize("NFKC"));
}
// a label spelled over two or three tokens (mot de passe, kata sandi, API key): the joined words must BE a label
function isGateLabelExact(joined) {
  const w = joined
    .toLowerCase()
    .normalize("NFKC")
    .replace(/[^\p{L}\p{N}]/gu, "");
  return inLabelSet(GATE_LABELS, w);
}
// n8n credential type identifiers (httpHeaderAuth, slackApi, googleSheetsOAuth2Api) are part of every pack
const CRED_TYPE_ID =
  /^[a-z][a-z0-9]*(?:[A-Z][a-z0-9]*)*(?:Auth|Api|OAuth2|OAuth2Api)$/;
function isGateLabel(tok) {
  if (CRED_TYPE_ID.test(tok.replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, "")))
    return false;
  if (hasGlued(tok)) return true;
  const w = gateWords(tok);
  for (let a = 0; a < w.length; a++) {
    for (let b = a + 1; b <= Math.min(w.length, a + 3); b++)
      if (inLabelSet(GATE_LABELS, w.slice(a, b).join(""))) return true;
  }
  return false;
}
const isRedacted = (v) =>
  /^[\s"'`(\[\\]*redacted[\s"'`)\]\\]*[.,;]?$/i.test(v) ||
  /^\[redacted/i.test(v);
const nonEmptyValue = (v) =>
  !!v &&
  /[\p{L}\p{N}]/u.test(v) &&
  !isRedacted(v) &&
  !/^[<]/.test(v) &&
  !isGateLabel(v);

/**
 * Any non-empty value after a credential label (any language, compounds included) with an assignment
 * marker (: = is -> ...) is a finding. This is the gate's job when the scrubber misses something.
 */
const STRONG_GATE = new Set(
  [...STRONG_LABELS].filter((w) => !/^(pass|sk|pw|pwd)$/.test(w)),
);
function isGateStrong(tok) {
  const w = gateWords(tok);
  for (let a = 0; a < w.length; a++)
    for (let b = a + 1; b <= Math.min(w.length, a + 3); b++)
      if (inLabelSet(STRONG_GATE, w.slice(a, b).join(""))) return true;
  return false;
}

// strong (password, pin, passcode, secret, rootpassword, kata sandi ...) or weak (token, key, auth, login ...)
// for a label text; PIN-type code words count as strong. Null when the text is not a label at all.
const STRONG_SUFFIX = SUFFIX_LABELS.filter(
  (l) => STRONG_LABELS.has(l) || PIN_LABELS.has(l),
);
function strongLabel(text) {
  const w = gateWords(text);
  for (let a = 0; a < w.length; a++)
    for (let b = a + 1; b <= Math.min(w.length, a + 3); b++) {
      const s = w.slice(a, b).join("");
      if (inLabelSet(STRONG_LABELS, s) || inLabelSet(PIN_LABELS, s))
        return true;
    }
  return w.some((x) =>
    STRONG_SUFFIX.some((l) => x.length > l.length && x.endsWith(l)),
  );
}
function labelKind(text) {
  if (strongLabel(text)) return "strong";
  return isGateLabel(text) ? "weak" : null;
}

function labelValuePass(line, add) {
  // tokens as before; `breaks` marks the first token of each markup segment (a table cell, a tag)
  const toks = [];
  const breaks = new Set();
  line.split(/<[^>]*>/).forEach((seg) => {
    const ws = seg.replace(/\|/g, " ").split(/\s+/).filter(Boolean);
    if (ws.length && toks.length) breaks.add(toks.length);
    toks.push(...ws);
  });
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.startsWith("$") || t.includes("://")) continue;
    // a name quoted by the pack itself (“name”) is not an assignment
    if (/[\u201d\u2019\u00bb]$/.test(t.replace(/[:=,.;]+$/, ""))) continue;
    // attached: DB-Password:Winter25x, API_TOKEN=abc, "password":"x"
    const m = /^["'`(\[]*([^:=\s"'`]{1,48})["'`]?([:=])["'`]?(.*)$/u.exec(t);
    if (m && isGateLabel(m[1])) {
      const v = m[3].replace(/^["'`]+|["'`,;]+$/g, "");
      const kind = labelKind(m[1]);
      if (nonEmptyValue(v) && isLabelledValue(kind, v)) {
        add("credential label with an attached value");
        continue;
      }
      if (
        !v &&
        i + 1 < toks.length &&
        nonEmptyValue(toks[i + 1]) &&
        isLabelledValue(kind, toks[i + 1]) &&
        !MARK_TOKENS.has(toks[i + 1])
      ) {
        add("credential label followed by a value");
        continue;
      }
      continue;
    }
    // a label of one to three words, then a marker, then a value
    let span = 0;
    if (isGateLabel(t)) span = 1;
    else if (i + 1 < toks.length && isGateLabelExact(t + toks[i + 1])) span = 2;
    else if (
      i + 2 < toks.length &&
      isGateLabelExact(t + toks[i + 1] + toks[i + 2])
    )
      span = 3;
    if (!span || (span === 1 && !isGateLabel(t))) continue;
    let p = i + span;
    let marked = /[:=]$/.test(toks[p - 1]);
    const markToks = [];
    if (!marked && p < toks.length && MARK_TOKENS.has(toks[p].toLowerCase())) {
      marked = true;
      markToks.push(toks[p]);
      p++;
    }
    while (marked && p < toks.length && MARK_TOKENS.has(toks[p].toLowerCase()))
      markToks.push(toks[p++]);
    // only a dash (never a colon or "=") makes a plain-letter run a name: "Credentials - Slack" is prose,
    // "Credentials: Slack" and "password: tangerine" stay values
    const dashOnly =
      !/[:=]$/.test(toks[i + span - 1]) &&
      markToks.length > 0 &&
      markToks.every((t) => DASH_MARKS.has(t));
    if (!marked) {
      // "the password for the CRM is X": a marker word a few words later
      if (isGateStrong(toks.slice(i, i + span).join("")))
        for (let q = p; q < Math.min(toks.length, p + 6); q++)
          if (/^(is|=|=>|\u2192)$/i.test(toks[q])) {
            marked = true;
            p = q + 1;
            break;
          }
    }
    const kind = labelKind(toks.slice(i, i + span).join(""));
    const val =
      p < toks.length ? toks[p].replace(/^["'`]+|["'`,;]+$/g, "") : "";
    if (marked && nonEmptyValue(val) && isLabelledValue(kind, val)) {
      // ordinary names ("Credentials - Slack.", "Password - Reset Flow") are not values
      if (dashOnly && plainRun(toks, p, breaks)) continue;
      add("credential label followed by an assigned value");
    }
  }
}

const labelWord = (t) => {
  const w = t.replace(EDGE, "").toLowerCase();
  return LABEL_SET.has(w) || LABEL_SET.has(w.replace(/[-_\s]/g, ""));
};

/** Scan one text. Returns [{line, kind}] */
function scanText(text) {
  const hits = [];
  String(text)
    .split("\n")
    .forEach((raw, i) => {
      const line = decodeLine(raw);
      const tokens = line.split(SPLIT).filter(Boolean);
      const seen = new Set();
      const add = (kind) => {
        if (!seen.has(kind)) {
          seen.add(kind);
          hits.push({ line: i + 1, kind });
        }
      };
      labelValuePass(line, add);
      // CJK / Hangul / Kana labels inside tokens: 密码是蓝天白云88, パスワード:さくら77
      for (const lab of CJK_LABELS) {
        const at = line.indexOf(lab);
        if (at < 0) continue;
        // what directly follows the label (skipping separators) must not be markup or a redaction marker
        const rest = line
          .slice(at + lab.length)
          .replace(/^[\s:\uff1a=\u662f\u4e3a]+/u, "");
        if (
          /^[\p{L}\p{N}]/u.test(rest) &&
          /\p{N}|[A-Za-z]/u.test(rest.split(/[\s|<\]\[()]/)[0].slice(0, 24))
        )
          add("credential label followed by a value");
      }
      // an emoji label with an explicit colon takes whatever follows ("🔐: winter phrase")
      for (const e of EMOJI_LABELS) {
        let from = 0;
        for (
          let at = line.indexOf(e, from);
          at >= 0;
          at = line.indexOf(e, from)
        ) {
          from = at + e.length;
          const after = line.slice(from).replace(/^️/u, "");
          const m = /^\s*[:=]\s*(\S+)/u.exec(after);
          if (
            m &&
            !/^\\?\[?redacted/i.test(m[1]) &&
            /^[\p{L}\p{N}]/u.test(m[1])
          )
            add("emoji label with a colon followed by text");
        }
      }
      // spaced digit runs (4 8 1 5 9 2) and grouped numbers (cards, IBANs)
      let run = 0;
      let grp = 0;
      for (const t of tokens) {
        run = /^\p{Nd}$/u.test(t) ? run + 1 : 0;
        grp = /^\d{3,4}$/.test(t) ? grp + 1 : 0;
        if (run === 5) add("spaced digit run");
        if (grp === 3) add("grouped number");
      }
      if (/\b\d{3}-\d{2}-\d{4}\b/.test(line)) add("SSN-like number");
      tokens.forEach((t, k) => {
        const r = suspiciousToken(t);
        if (r) add(r);
        // a label of one, two or three words (password, kata sandi, mot de passe)
        let span = 0;
        if (isGateLabel(t)) span = 1;
        else if (isGateLabelExact(t + (tokens[k + 1] || ""))) span = 2;
        else if (
          isGateLabelExact(t + (tokens[k + 1] || "") + (tokens[k + 2] || ""))
        )
          span = 3;
        if (
          span &&
          isGateStrong(tokens.slice(k, k + span).join("")) &&
          !/^\[?redacted/i.test(t)
        ) {
          for (const nx of tokens.slice(k + span, k + span + 5)) {
            if (/^\\?\[?redacted/i.test(nx)) break;
            if (valueLike(nx)) {
              add("credential word followed by a value");
              break;
            }
          }
        }
        if (CODE_WORDS.has(t.replace(EDGE, "").toLowerCase())) {
          let d = 0;
          for (const nx of tokens.slice(k + 1, k + 10))
            d += /^\p{Nd}$/u.test(nx) ? 1 : 0;
          if (d >= 4) add("code label followed by spaced digits");
        }
        // pin / door code / otp followed by digits, spoken digits or NATO words
        const lab1 = t.replace(EDGE, "").toLowerCase().replace(/[-_]/g, "");
        const lab2 =
          lab1 + (tokens[k + 1] || "").replace(EDGE, "").toLowerCase();
        const pinAt = inLabelSet(PIN_LABELS, lab1)
          ? 1
          : inLabelSet(PIN_LABELS, lab2)
            ? 2
            : 0;
        if (pinAt) {
          const after = tokens.slice(k + pinAt, k + pinAt + 7);
          if (
            after.some(
              (x) =>
                (x.match(/\p{Nd}/gu) || []).length >= 3 &&
                !/\p{L}{3,}/u.test(x),
            )
          )
            add("code label followed by digits");
          let sp = 0;
          let na = 0;
          for (const x of after) {
            const w = x.toLowerCase().replace(/[^\p{L}]/gu, "");
            sp = SPOKEN_DIGITS.has(w) ? sp + 1 : 0;
            na = NATO.has(w) ? na + 1 : 0;
            if (sp === 3) add("code label followed by spoken digits");
            if (na === 2) add("code label followed by NATO words");
          }
        }
        // emoji labels (key, lock) followed by a value
        // glued form: key-emoji followed directly by the value
        const glued = EMOJI_LABELS.find(
          (e) => t.startsWith(e) && t.length > e.length,
        );
        if (glued) {
          const restG = t.slice(glued.length).replace(/^[️:=]+/u, "");
          if (restG && (valueLike(restG) || /\p{N}/u.test(restG)))
            add("emoji label followed by a value");
        }
        if (EMOJI_LABELS.includes(t.replace(/[️:=]/g, ""))) {
          for (const nx of tokens.slice(k + 1, k + 4)) {
            if (/^\\?\[?redacted/i.test(nx)) break;
            if (
              valueLike(nx) ||
              ((/\p{N}/u.test(nx) || /[!@#$%^&*+~]/.test(nx)) &&
                codePoints(nx).length >= 3)
            ) {
              add("emoji label followed by a value");
              break;
            }
          }
        }
      });
    });
  return hits;
}

const blank = (m) => m.replace(/[^\n]/g, "");

/** Scan every file of a pack. Returns [{file,line,kind,source}] */
function scanPack(files, { mermaidUrl = "", mermaidSri = "" } = {}) {
  const out = [];
  for (const [file, content] of Object.entries(files)) {
    let text = content;
    if (file.endsWith(".html")) {
      if (mermaidUrl) text = text.split(mermaidUrl).join("");
      if (mermaidSri) text = text.split(mermaidSri).join("");
      text = text
        .replace(/<style>[\s\S]*?<\/style>/, blank)
        .replace(/<script>[\s\S]*?<\/script>/, blank)
        .replace(/<meta [^>]*>/g, "");
    }
    for (const h of scanText(text))
      out.push({ file, line: h.line, kind: h.kind, source: "builtin" });
  }
  return out;
}

/** 'available' | 'absent' | 'broken' */
function gitleaksStatus() {
  try {
    const r = cp.spawnSync("gitleaks", ["version"], {
      encoding: "utf8",
      timeout: 15000,
    });
    if (r.error) return r.error.code === "ENOENT" ? "absent" : "broken";
    return r.status === 0 ? "available" : "broken";
  } catch {
    return "broken";
  }
}
const gitleaksAvailable = () => gitleaksStatus() === "available";

/** Run gitleaks over the finished pack (written to a temp dir). Returns {ran, status, findings} */
function runGitleaks(files) {
  const status = gitleaksStatus();
  if (status === "absent") return { ran: false, status, findings: [] };
  if (status === "broken") {
    return {
      ran: false,
      status,
      findings: [
        {
          file: "(gitleaks)",
          line: 0,
          kind: 'gitleaks is installed but broken (it did not answer "gitleaks version"); failing closed',
          source: "gitleaks",
        },
      ],
    };
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "handover-gate-"));
  const report = `${dir}.json`;
  try {
    for (const [f, c] of Object.entries(files))
      fs.writeFileSync(path.join(dir, f), c, "utf8");
    const r = cp.spawnSync(
      "gitleaks",
      [
        "detect",
        "--no-git",
        "--source",
        dir,
        "--no-banner",
        "--redact",
        "--report-format",
        "json",
        "--report-path",
        report,
      ],
      { encoding: "utf8", timeout: 120000 },
    );
    const findings = [];
    if (r.status === 1 && fs.existsSync(report)) {
      for (const f of JSON.parse(fs.readFileSync(report, "utf8") || "[]")) {
        findings.push({
          file: path.basename(String(f.File || "")),
          line: f.StartLine,
          kind: `gitleaks: ${f.RuleID}`,
          source: "gitleaks",
        });
      }
    } else if (r.status !== 0 && r.status !== 1) {
      findings.push({
        file: "(gitleaks)",
        line: 0,
        kind: "gitleaks failed to run; failing closed",
        source: "gitleaks",
      });
    }
    return { ran: true, status, findings };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(report, { force: true });
  }
}

module.exports = {
  scanText,
  scanPack,
  runGitleaks,
  gitleaksAvailable,
  gitleaksStatus,
  suspiciousToken,
};
