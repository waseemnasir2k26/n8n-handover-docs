"use strict";
const { clean } = require("./util");

// Encode anything that can break out of a quoted Mermaid label.
function mLabel(s, max = 60) {
  let t = clean(s);
  if (t.length > max) t = t.slice(0, max - 1) + "…";
  return t.replace(/[&"<>`\\|%#;{}[\]()]/g, (c) => `#${c.charCodeAt(0)};`);
}

function shape(n, label) {
  const l = `"${label}"`;
  if (n.kind === "trigger") return `([${l}])`;
  if (n.kind === "branch") return `{${l}}`;
  if (n.kind === "sub") return `(${l})`;
  return `[${l}]`;
}

/** Flowchart source for one analysed workflow. Nodes + connections, branches labelled. */
function toMermaid(m) {
  const lines = ["flowchart TD"];
  const shown = m.nodes.filter((n) => n.kind !== "note");
  if (!shown.length) {
    lines.push('  empty["(no nodes)"]');
    return lines.join("\n");
  }
  for (const n of shown) {
    const label = `${mLabel(n.name)}<br/>${mLabel(n.typeLabel, 30)}`;
    lines.push(`  ${n.id}${shape(n, label)}`);
  }
  for (const e of m.edges) {
    const l = e.label ? `|"${mLabel(e.label, 30)}"|` : "";
    lines.push(
      e.type === "main"
        ? `  ${e.from} -->${l} ${e.to}`
        : `  ${e.from} -.->${l} ${e.to}`,
    );
  }
  lines.push("  classDef trig fill:#e8f5e9,stroke:#2e7d32;");
  lines.push("  classDef sub fill:#f3e5f5,stroke:#6a1b9a;");
  lines.push(
    "  classDef off fill:#eee,stroke:#999,color:#777,stroke-dasharray: 4 3;",
  );
  const t = shown.filter((n) => n.kind === "trigger").map((n) => n.id);
  const s = shown.filter((n) => n.kind === "sub").map((n) => n.id);
  const o = shown.filter((n) => n.disabled).map((n) => n.id);
  if (t.length) lines.push(`  class ${t.join(",")} trig;`);
  if (s.length) lines.push(`  class ${s.join(",")} sub;`);
  if (o.length) lines.push(`  class ${o.join(",")} off;`);
  return lines.join("\n");
}

module.exports = { toMermaid, mLabel };
