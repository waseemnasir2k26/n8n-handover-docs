'use strict';

const CONTROL = new RegExp('[' + [[0, 8], [11, 12], [14, 31], [127, 127], [0x2028, 0x2029], [0x202a, 0x202e], [0x2066, 0x2069]].map(([a, b]) => String.fromCharCode(a) + (b > a ? '-' + String.fromCharCode(b) : '')).join('') + ']', 'g');

const CONTROL_NO_NL = new RegExp('[' + [[0, 9], [11, 12], [14, 31], [127, 127], [0x2028, 0x2029], [0x202a, 0x202e], [0x2066, 0x2069]].map(([a, b]) => String.fromCharCode(a) + (b > a ? '-' + String.fromCharCode(b) : '')).join('') + ']', 'g');

function clean(v) {
  return String(v == null ? '' : v).replace(CONTROL, '').replace(/[\r\n\t]+/g, ' ');
}

function esc(v) {
  return clean(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Markdown-safe inline text (GitHub flavoured). Never used for code spans.
// Like esc() but keeps line breaks (used for <pre> blocks of generated diagram text).
function escPre(v) {
  return String(v == null ? '' : v)
    .replace(CONTROL_NO_NL, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function mdEsc(v) {
  return clean(v)
    .replace(/\b(javascript|vbscript|data)\s*:/gi, "$1&#58;")
    .replace(/&/g, '&amp;')
    .replace(/[\\`*_[\]<>|~]/g, (c) => (c === '<' ? '&lt;' : c === '>' ? '&gt;' : '\\' + c))
    .replace(/^(\s*)([#+\-=]|\d+\.)/, '$1\\$2');
}

function mdCode(v) {
  const s = clean(v).replace(/`/g, "'");
  return '`' + s + '`';
}

// File name: the workflow's safe words (letters, numbers up to 4 digits) plus, when something was
// redacted or the name collides, a short stable hash. Never "redacted-N".
function slugify(name, taken, seed) {
  const raw = String(name == null ? '' : name);
  const redacted = /redacted/i.test(raw);
  // accents are transliterated (zurücksetzen -> zurucksetzen); other scripts have no safe words
  const words = raw
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toLowerCase()
    .replace(/redacted/g, ' ')
    .split(/[^a-z0-9]+/)
    .filter((w) => w && (/^[a-z]+$/.test(w) || /^\d{1,4}$/.test(w) || (w.length <= 4 && /^[a-z0-9]+$/.test(w))));
  const base = words.join('-').slice(0, 60).replace(/-+$/g, '') || 'workflow';
  // "h" + 6 hex digits: a fixed, recognisable shape (the final gate allowlists it)
  const h = 'h' + require('node:crypto').createHash('sha256').update(String(seed == null ? raw : seed)).digest('hex').slice(0, 6);
  const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9]|index)$/;
  let s = redacted || !words.length ? `${base}-${h}` : base;
  if (RESERVED.test(s)) s = `${s}-wf`;
  if (taken.has(s)) s = `${base}-${h}`;
  let i = 2;
  while (taken.has(s) || RESERVED.test(s)) s = `${base}-${h}-${i++}`;
  taken.add(s);
  return s;
}

// CSV cell: quote everything, neutralise spreadsheet formula injection.
function csvCell(v) {
  let s = clean(v);
  if (/^\s*[=+\-@|%]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}

function csvRow(cells) {
  return cells.map(csvCell).join(',');
}

function walkStrings(value, cb, path = '', depth = 0) {
  if (depth > 14 || value == null) return;
  if (typeof value === 'string') {
    cb(value.length > 200000 ? value.slice(0, 200000) : value, path);
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => walkStrings(v, cb, `${path}[${i}]`, depth + 1));
  } else if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      walkStrings(v, cb, path ? `${path}.${k}` : k, depth + 1);
    }
  }
}

function uniq(arr) {
  return [...new Set(arr)];
}

function trunc(s, n) {
  s = clean(s);
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

module.exports = { clean, esc, escPre, mdEsc, mdCode, slugify, csvCell, csvRow, walkStrings, uniq, trunc };
