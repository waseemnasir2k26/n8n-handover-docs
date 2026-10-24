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

function slugify(name, taken) {
  let base = String(name == null ? '' : name)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60)
    .replace(/-+$/g, '');
  if (!base) base = 'workflow';
  let s = base;
  let i = 2;
  while (taken.has(s) || s === 'index') s = `${base}-${i++}`;
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
