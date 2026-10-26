"use strict";
const { esc, escPre, mdEsc, csvRow } = require("./util");

const MERMAID_VERSION = "11.4.1";
const MERMAID_SRI =
  "sha384-rbtjAdnIQE/aQJGEgXrVUlMibdfTSa4PQju4HDhN3sR2PmaKFzhEafuePsl9H/9I";
const MERMAID_URL = `https://cdn.jsdelivr.net/npm/mermaid@${MERMAID_VERSION}/dist/mermaid.min.js`;

// ---------- Markdown
function mdCell(c) {
  if (c && typeof c === "object") return `[${mdEsc(c.text)}](${c.md})`;
  return mdEsc(c);
}
function mdItem(c) {
  if (c && typeof c === "object")
    return `${mdEsc(c.prefix || "")}[${mdEsc(c.text)}](${c.md})`;
  return mdEsc(c);
}

function blocksToMd(blocks) {
  const out = [];
  for (const b of blocks) {
    switch (b.t) {
      case "h":
        out.push(`${"#".repeat(b.l)} ${mdEsc(b.text)}`, "");
        break;
      case "p":
        out.push(mdEsc(b.text), "");
        break;
      case "note":
        out.push(
          `> ${b.kind === "warn" ? "**Warning:** " : "**Note:** "}${mdEsc(b.text)}`,
          "",
        );
        break;
      case "ul":
        b.items.forEach((i) => out.push(`- ${mdItem(i)}`));
        out.push("");
        break;
      case "ol":
        b.items.forEach((i, n) => out.push(`${n + 1}. ${mdItem(i)}`));
        out.push("");
        break;
      case "table":
        out.push(
          `| ${b.head.map(mdCell).join(" | ")} |`,
          `| ${b.head.map(() => "---").join(" | ")} |`,
        );
        b.rows.forEach((r) => out.push(`| ${r.map(mdCell).join(" | ")} |`));
        out.push("");
        break;
      case "mermaid":
        out.push("```mermaid", b.src, "```", "");
        break;
      default:
        break;
    }
  }
  return out.join("\n");
}

// ---------- HTML
function hCell(c) {
  if (c && typeof c === "object")
    return `<a href="${esc(c.html)}">${esc(c.text)}</a>`;
  return esc(c);
}
function hItem(c) {
  if (c && typeof c === "object")
    return `${esc(c.prefix || "")}<a href="${esc(c.html)}">${esc(c.text)}</a>`;
  return esc(c);
}

function blocksToHtml(blocks, ctx) {
  const out = [];
  for (const b of blocks) {
    switch (b.t) {
      case "h":
        out.push(
          `<h${b.l}${b.id ? ` id="${esc(b.id)}"` : ""}>${esc(b.text)}</h${b.l}>`,
        );
        break;
      case "p":
        out.push(`<p>${esc(b.text)}</p>`);
        break;
      case "note":
        out.push(
          `<p class="note ${b.kind === "warn" ? "warn" : "info"}"><strong>${b.kind === "warn" ? "Warning:" : "Note:"}</strong> ${esc(b.text)}</p>`,
        );
        break;
      case "ul":
        out.push(
          `<ul>${b.items.map((i) => `<li>${hItem(i)}</li>`).join("")}</ul>`,
        );
        break;
      case "ol":
        out.push(
          `<ol>${b.items.map((i) => `<li>${hItem(i)}</li>`).join("")}</ol>`,
        );
        break;
      case "table":
        out.push(
          `<div class="tw"><table><thead><tr>${b.head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${b.rows.map((r) => `<tr>${r.map((c) => `<td>${hCell(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`,
        );
        break;
      case "mermaid":
        out.push(
          ctx.offline
            ? `<details open><summary>Diagram shown as text: ${esc(ctx.fallbackReason || "no script available")}. Paste into mermaid.live to view.</summary><pre class="src">${escPre(b.src)}</pre></details>`
            : `<div class="diagram"><pre class="mermaid">${escPre(b.src)}</pre></div><details class="srcbox"><summary>Diagram source (text fallback)</summary><pre class="src">${escPre(b.src)}</pre></details>`,
        );
        break;
      default:
        break;
    }
  }
  return out.join("\n");
}

const CSS = `
:root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--line:#d0d7de;--acc:#0b5fff;--warn:#fff4ce;--info:#e7f0ff}
@media (prefers-color-scheme:dark){:root{--bg:#0f1419;--fg:#e6e9ee;--mut:#9aa4b2;--line:#2b3440;--acc:#7aa8ff;--warn:#3a3112;--info:#13233f}}
*{box-sizing:border-box}body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1040px;margin:0 auto}h1{font-size:28px}h2{font-size:22px;margin-top:36px;border-bottom:1px solid var(--line);padding-bottom:6px}h3{font-size:16px;margin-top:22px}
a{color:var(--acc)}.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13.5px}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{background:rgba(127,127,127,.12)}
.note{padding:8px 12px;border-radius:6px;border:1px solid var(--line)}.warn{background:var(--warn)}.info{background:var(--info)}
pre{overflow:auto;padding:10px;border:1px solid var(--line);border-radius:6px;font-size:12.5px}.diagram{overflow:auto;border:1px solid var(--line);border-radius:6px;padding:8px;margin:8px 0}.diagram pre.mermaid{border:0;background:none}
section.wf{margin-top:48px}button{font:inherit;padding:6px 12px;border:1px solid var(--line);border-radius:6px;background:transparent;color:var(--fg);cursor:pointer}
@media print{body{font-size:11px;padding:0}button,.srcbox,nav{display:none!important}section.wf{page-break-before:always}table,.diagram,.note{page-break-inside:avoid}.tw{overflow:visible}a{color:inherit;text-decoration:none}pre.mermaid{white-space:pre-wrap}details{display:block}}
@page{margin:14mm}
`;

function htmlPage({ title, indexBlocks, sections, offline, fallbackReason }) {
  const ctx = { offline, fallbackReason };
  const csp = offline
    ? "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
    : "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src https://cdn.jsdelivr.net 'unsafe-inline'; base-uri 'none'; form-action 'none'";
  const script = offline
    ? ""
    : `
<script src="${MERMAID_URL}" integrity="${MERMAID_SRI}" crossorigin="anonymous"></script>
<script>
(function(){
  if(!window.mermaid){return;}
  mermaid.initialize({startOnLoad:false,securityLevel:'strict',theme:'neutral',maxTextSize:500000,maxEdges:5000});
  var els=document.querySelectorAll('pre.mermaid');
  els.forEach(function(el,i){
    mermaid.render('mmd'+i,el.textContent).then(function(r){
      var d=document.createElement('div');d.className='rendered';d.innerHTML=r.svg;
      el.parentNode.replaceChild(d,el);
    }).catch(function(){
      var p=document.createElement('p');p.className='note warn';p.textContent='Diagram could not be drawn (the Mermaid script did not load or rejected the diagram). The text version is below.';
      el.parentNode.insertBefore(p,el);
      var sb=el.parentNode.parentNode.querySelector('.srcbox');if(sb){sb.open=true;}
    });
  });
})();
</script>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex">
<title>${esc(title)}</title><style>${CSS}</style></head>
<body><main>
<p><button onclick="window.print()">Print / save as PDF</button></p>
${blocksToHtml(indexBlocks, ctx)}
${sections.map((s) => `<section class="wf" id="wf-${esc(s.slug)}">\n${blocksToHtml(s.blocks, ctx)}\n</section>`).join("\n")}
<p class="note info">Generated by n8n-handover-docs. No credential values, credential IDs or API keys are written to this file.</p>
</main>${script}</body></html>
`;
}

// ---------- CSV
function inventoryCsv(items) {
  const rows = [
    csvRow([
      "workflow",
      "active",
      "service",
      "credential_name",
      "credential_type",
      "nodes",
    ]),
  ];
  for (const { m } of items) {
    const active = m.active === null ? "" : String(m.active);
    const seenCred = new Set();
    for (const s of m.services) {
      if (!s.credentials.length)
        rows.push(csvRow([m.name, active, s.name, "", "", s.nodes.join("; ")]));
      for (const c of s.credentials) {
        seenCred.add(`${c.type}\u0000${c.name}`);
        rows.push(
          csvRow([m.name, active, s.name, c.name, c.type, s.nodes.join("; ")]),
        );
      }
    }
    for (const c of m.credentials) {
      if (!seenCred.has(`${c.type}\u0000${c.name}`))
        rows.push(
          csvRow([m.name, active, "", c.name, c.type, c.nodes.join("; ")]),
        );
    }
    if (!m.services.length && !m.credentials.length)
      rows.push(csvRow([m.name, active, "", "", "", ""]));
  }
  // LF, not CRLF: matches .gitattributes (eol=lf), so a demo run leaves no git diff
  return rows.join("\n") + "\n";
}

module.exports = {
  blocksToMd,
  blocksToHtml,
  htmlPage,
  inventoryCsv,
  MERMAID_URL,
  MERMAID_VERSION,
  MERMAID_SRI,
};
