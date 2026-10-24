"use strict";
// INDEPENDENT final gate. Deliberately shares no code with the scrubber
// (src/policy.js): it classifies every token of the finished output by character
// classes, length and entropy, also after base64 / %-decoding, and looks for
// credential words followed by a value-looking token. Reports file:line and a
// kind, never the value. When gitleaks is on PATH it is run as a second,
// third-party detector over the same files.
const cp = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const WORDS =
  /(pass|pwd|secret|token|apikey|api_key|auth|bearer|login|cred|private|\bpw\b|\bsk[-_])/i;
const SPLIT = /[\s"'<>()[\]{},;|=:\\]+/;
const STANDALONE =
  /^(pass(word|wd|phrase|code)?|pwd|pw|secret|secrets|token|tokens|api[_-]?key|apikey|auth|authorization|bearer|login|credentials?|creds?|private|sk[-_].*)$/i;

function shannon(s) {
  const m = new Map();
  for (const c of s) m.set(c, (m.get(c) || 0) + 1);
  let h = 0;
  for (const n of m.values()) h -= (n / s.length) * Math.log2(n / s.length);
  return h;
}

function classes(t) {
  return (
    (/[a-z]/.test(t) ? 1 : 0) +
    (/[A-Z]/.test(t) ? 1 : 0) +
    (/\d/.test(t) ? 1 : 0) +
    (/[^A-Za-z0-9]/.test(t) ? 1 : 0)
  );
}

function isSlug(t) {
  // lowercase words / short numbers joined by - . _ / (file names, anchors, ids like lg-04)
  return (
    /^[a-z0-9]+([-._/][a-z0-9]+)+$/.test(t) &&
    t
      .split(/[-._/]/)
      .every((p) => p.length <= 14 && (p.match(/\d/g) || []).length <= 4)
  );
}

function valueLike(t) {
  const c = t.replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9!@#$%^&*+~]+$/g, "");
  if (c.length < 6) return false;
  if (/^\[?redacted\]?$/i.test(c)) return false;
  return (/\d/.test(c) && /[A-Za-z]/.test(c)) || /[!@#$%^&*+~]/.test(c);
}

function suspiciousToken(t, depth = 0) {
  const c = t.replace(/^[^A-Za-z0-9]+/, "").replace(/[.,;)\]}>'"…_/-]+$/, "");
  if (c.length < 8) return null;
  const digits = (c.match(/\d/g) || []).length;
  const alpha = /[A-Za-z]/.test(c);
  if (/[0-9a-fA-F]{16,}/.test(c)) return "hex run";
  if (!isSlug(c)) {
    if (c.length >= 20 && digits >= 2 && classes(c) >= 3 && shannon(c) >= 3.4)
      return "high-entropy token";
    if (c.length >= 12 && alpha && digits >= 2) return "letters+digits token";
    if (c.length >= 8 && alpha && digits >= 1 && /[!@#$%^&*+~?]/.test(c))
      return "password-like token";
    if (c.length >= 10 && /[a-z]/.test(c) && /[A-Z]/.test(c) && digits >= 2)
      return "mixed-case+digit token";
  }
  if (depth < 2) {
    if (/%[0-9a-fA-F]{2}/.test(c)) {
      try {
        const d = decodeURIComponent(c);
        const r =
          suspiciousToken(d, depth + 1) ||
          (WORDS.test(d) && d.split(SPLIT).some(valueLike)
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
          WORDS.test(d) ||
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
      tokens.forEach((t, k) => {
        const r = suspiciousToken(t);
        if (r) add(r);
        if (
          STANDALONE.test(t.replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, "")) &&
          !/^\[?redacted/i.test(t)
        ) {
          for (const nx of tokens.slice(k + 1, k + 6)) {
            if (valueLike(nx)) {
              add("credential word followed by a value");
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

function gitleaksAvailable() {
  try {
    const r = cp.spawnSync("gitleaks", ["version"], {
      encoding: "utf8",
      timeout: 15000,
    });
    return r.status === 0;
  } catch {
    return false;
  }
}

/** Run gitleaks over the finished pack (written to a temp dir). Returns {ran, findings} */
function runGitleaks(files) {
  if (!gitleaksAvailable()) return { ran: false, findings: [] };
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
        kind: "gitleaks failed to run; treated as a finding",
        source: "gitleaks",
      });
    }
    return { ran: true, findings };
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
  suspiciousToken,
};
