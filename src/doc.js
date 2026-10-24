"use strict";
// Build a small neutral block list from analysed workflows. Renderers (md/html)
// do all escaping, so nothing here needs to be pre-escaped.
const { toMermaid } = require("./mermaid");
const { FAIL, BUILTIN_NOTES } = require("./rules");
const { maskDesc } = require("./secrets");

const link = (text, md, html) => ({ text, md, html });
const yn = (v) => (v === true ? "yes" : v === false ? "no" : "unknown");

function runbookRows(m) {
  const rows = [];
  for (const s of m.services) {
    const list = FAIL[s.cat] || FAIL.apikey;
    const where = `Node(s): ${s.nodes.join(", ")}`;
    for (const [what, why, check] of list)
      rows.push([s.name, what, why, `${where}. ${check}`]);
  }
  const trig = m.triggers.filter((t) => !t.disabled);
  const add = (key, where, name) => {
    const [a, b, c] = BUILTIN_NOTES[key];
    rows.push([name, a, b, `${where}. ${c}`]);
  };
  if (trig.some((t) => t.kind === "schedule"))
    add(
      "schedule",
      `Node(s): ${trig
        .filter((t) => t.kind === "schedule")
        .map((t) => t.node)
        .join(", ")}`,
      "Schedule trigger",
    );
  if (m.webhooks.length)
    add(
      "webhook",
      `Node(s): ${m.webhooks.map((w) => w.node).join(", ")}`,
      "Webhook trigger",
    );
  if (
    m.webhooks.some(
      (w) => w.auth === "none" && /webhook$/i.test(w.node) === false,
    ) ||
    m.warnings.some((w) => w.startsWith('Webhook "'))
  ) {
    rows.push([
      "Webhook trigger",
      ...BUILTIN_NOTES["webhook-open"].slice(0, 2),
      `Node(s): ${
        m.webhooks
          .filter((w) => w.auth === "none")
          .map((w) => w.node)
          .join(", ") || "webhook node"
      }. ${BUILTIN_NOTES["webhook-open"][2]}`,
    ]);
  }
  if (m.codeNodes.length)
    add("code", `Node(s): ${m.codeNodes.join(", ")}`, "Code nodes");
  if (m.subWorkflows.length)
    add(
      "subworkflow",
      `Node(s): ${m.subWorkflows.map((s) => s.node).join(", ")}`,
      "Sub-workflows",
    );
  if (m.agents.length)
    add(
      "agent",
      `Node(s): ${m.agents.map((a) => a.node).join(", ")}`,
      "AI agent",
    );
  return rows;
}

function workflowBlocks(m, opts = {}) {
  const b = [];
  const byId = new Map(m.nodes.map((n) => [n.id, n]));
  b.push({ t: "h", l: 2, text: m.name, id: opts.anchor });
  b.push({ t: "p", text: m.summary });
  if (opts.llm)
    b.push({
      t: "note",
      kind: "info",
      text: `AI-written summary (${opts.llm.provider}; unverified, written from node names, types and connections only): ${opts.llm.text}`,
    });

  b.push({
    t: "table",
    head: ["Item", "Value"],
    rows: [
      ["Active", yn(m.active)],
      ["Nodes", String(m.nodeCount)],
      ["Tags", m.tags.join(", ") || "none"],
      [
        "Trigger",
        m.triggers
          .filter((t) => !t.disabled)
          .map((t) => `${t.node} (${t.kind})`)
          .join("; ") || "none",
      ],
      [
        "Schedule",
        m.triggers
          .map((t) => t.schedule)
          .filter(Boolean)
          .join("; ") || "not scheduled",
      ],
    ],
  });

  b.push({ t: "h", l: 3, text: "Flow" });
  b.push({ t: "mermaid", src: toMermaid(m) });

  b.push({ t: "h", l: 3, text: "Steps" });
  const stepItems = [];
  m.order.forEach((id, i) => {
    const n = byId.get(id);
    const outs = m.edges
      .filter((e) => e.from === id && e.type === "main")
      .map((e) => `${byId.get(e.to).name}${e.label ? ` (${e.label})` : ""}`);
    const attach = m.agents.find((a) => a.node === n.name);
    let line = `${n.name}: ${n.typeLabel}${n.detail ? `, ${n.detail}` : ""}${n.disabled ? " [DISABLED]" : ""}`;
    if (attach)
      line += `. Uses ${attach.parts.map((p) => `${p.label}: ${p.names.join(", ")}`).join("; ")}`;
    if (outs.length) line += `. Next: ${outs.join(", ")}`;
    stepItems.push(line);
  });
  if (stepItems.length) b.push({ t: "ol", items: stepItems });
  else b.push({ t: "p", text: "No steps found." });
  const extra = m.orphanSubs
    .map((id) => byId.get(id))
    .filter(
      (n) =>
        !m.agents.some((a) => a.parts.some((p) => p.names.includes(n.name))),
    );
  if (extra.length)
    b.push({
      t: "p",
      text: `Unattached helper nodes: ${extra.map((n) => n.name).join(", ")}`,
    });

  if (m.notes.length) {
    b.push({ t: "h", l: 3, text: "Notes left on the canvas" });
    b.push({ t: "ul", items: m.notes });
  }

  b.push({ t: "h", l: 3, text: "External services" });
  if (m.services.length)
    b.push({
      t: "table",
      head: ["Service", "Used by node(s)", "Credential(s) (name / type)"],
      rows: m.services.map((s) => [
        s.name,
        s.nodes.join(", "),
        s.credentials.map((c) => `${c.name} / ${c.type}`).join("; ") || "none",
      ]),
    });
  else b.push({ t: "p", text: "None." });

  b.push({
    t: "h",
    l: 3,
    text: "Credentials (names and types only, never values)",
  });
  if (m.credentials.length)
    b.push({
      t: "table",
      head: ["Name", "Type", "Node(s)"],
      rows: m.credentials.map((c) => [c.name, c.type, c.nodes.join(", ")]),
    });
  else b.push({ t: "p", text: "None attached." });

  b.push({
    t: "h",
    l: 3,
    text: "Environment variables and n8n variables referenced",
  });
  const e = m.env;
  if (e.env.length || e.vars.length || e.secrets.length) {
    b.push({
      t: "ul",
      items: [
        ...e.env.map((x) => `$env: ${x}`),
        ...e.vars.map((x) => `$vars: ${x}`),
        ...e.secrets.map((x) => `$secrets: ${x}`),
      ],
    });
  } else b.push({ t: "p", text: "None." });

  b.push({ t: "h", l: 3, text: "Webhooks" });
  if (m.webhooks.length)
    b.push({
      t: "table",
      head: ["Node", "Method", "Path", "URL", "Auth", "Responds"],
      rows: m.webhooks.map((w) => [
        w.node,
        w.method,
        w.path,
        w.url,
        w.auth,
        w.responseMode,
      ]),
    });
  else b.push({ t: "p", text: "None." });

  b.push({ t: "h", l: 3, text: "Error handling" });
  const eh = m.errorHandling;
  b.push({
    t: "ul",
    items: [
      eh.isErrorWorkflow
        ? "This workflow IS an error workflow (has an Error Trigger)."
        : eh.errorWorkflow.set
          ? `Error workflow: ${eh.errorWorkflow.name || "set (name not resolvable from this export)"}`
          : "Error workflow: not set",
      `Retry on fail: ${eh.retry.length ? eh.retry.join("; ") : "not used"}`,
      `Continue on fail: ${eh.continueOnFail.length ? eh.continueOnFail.join(", ") : "not used"}`,
      `Error output branch: ${eh.errorOutputs.length ? eh.errorOutputs.join(", ") : "not used"}`,
    ],
  });
  for (const g of eh.gaps) b.push({ t: "note", kind: "warn", text: g });

  b.push({ t: "h", l: 3, text: "Rate limits and caps" });
  if (m.caps.length) b.push({ t: "ul", items: m.caps });
  else b.push({ t: "p", text: "No explicit caps found in node settings." });

  b.push({ t: "h", l: 3, text: "Sub-workflows called" });
  if (m.subWorkflows.length) {
    b.push({
      t: "ul",
      items: m.subWorkflows.map((s) => {
        const label = `${s.node}${s.viaTool ? " (as an AI tool)" : ""} calls `;
        if (s.name && opts.slugByName && opts.slugByName.has(s.name))
          return {
            prefix: label,
            ...link(
              s.name,
              `${opts.slugByName.get(s.name)}.md`,
              `#wf-${opts.slugByName.get(s.name)}`,
            ),
          };
        return label + (s.name || "(workflow not found in this export)");
      }),
    });
  } else b.push({ t: "p", text: "None." });

  b.push({ t: "h", l: 3, text: "Warnings" });
  if (m.warnings.length || m.secrets.length) {
    const items = [...m.warnings];
    b.push({ t: "ul", items });
    if (m.secrets.length) {
      b.push({
        t: "table",
        head: ["Node", "Location", "What it looks like", "Value"],
        rows: m.secrets.map((s) => [
          s.node,
          s.path || "(value)",
          s.kind,
          maskDesc(s.len),
        ]),
      });
    }
  } else b.push({ t: "p", text: "None." });

  b.push({ t: "h", l: 3, text: "When it breaks" });
  const rows = runbookRows(m);
  if (rows.length)
    b.push({
      t: "table",
      head: ["Area", "Symptom", "Likely cause", "Where to look"],
      rows,
    });
  else
    b.push({
      t: "p",
      text: "Only built-in nodes: failures will be logic errors visible in the Executions list.",
    });
  b.push({
    t: "p",
    text: "First step for any failure: n8n > Executions > filter by this workflow > open the red execution > the failing node is highlighted and its error text is on the right.",
  });
  return b;
}

function indexBlocks(items, opts = {}) {
  const b = [];
  b.push({ t: "h", l: 1, text: opts.title || "n8n handover pack" });
  b.push({
    t: "p",
    text: `Generated ${opts.date}. ${items.length} workflow(s). Credential values and IDs are never copied into this pack.`,
  });
  const hidden = items.reduce((n, { m }) => n + m.hiddenNotes, 0);
  const redacted = items.reduce((n, { m }) => n + m.redactedNames, 0);
  const includeNotes = items.some(({ m }) => m.includeNotes);
  b.push({
    t: "note",
    kind: "info",
    text: `${hidden} sticky note(s) ${includeNotes ? "included, redacted best-effort" : "hidden (use --include-notes to include them; they are then redacted best-effort)"}. ${redacted} name(s) were partly replaced with [redacted] because they looked like they might contain a secret. This pack is best-effort: it was scanned by an independent detector before writing, but read it before you send it. ${opts.gitleaksNote || "independent gitleaks scan: not run"}.`,
  });
  b.push({ t: "h", l: 2, text: "Workflows" });
  b.push({
    t: "table",
    head: [
      "Workflow",
      "Active",
      "Trigger",
      "Services",
      "Credentials",
      "Error workflow",
      "Warnings",
    ],
    rows: items.map(({ m, slug }) => [
      link(m.name, `${slug}.md`, `#wf-${slug}`),
      yn(m.active),
      m.triggers
        .filter((t) => !t.disabled)
        .map((t) => t.kind)
        .join(", ") || "none",
      m.services.map((s) => s.name).join(", ") || "none",
      String(m.credentials.length),
      m.errorHandling.isErrorWorkflow
        ? "is one"
        : m.errorHandling.errorWorkflow.set
          ? "yes"
          : "no",
      String(m.warnings.length),
    ]),
  });
  // global lists
  const creds = new Map();
  for (const { m } of items)
    for (const c of m.credentials) {
      const k = `${c.type}\u0000${c.name}`;
      if (!creds.has(k)) creds.set(k, { ...c, wfs: [] });
      creds.get(k).wfs.push(m.name);
    }
  b.push({
    t: "h",
    l: 2,
    text: "Credentials to transfer or recreate (names and types only)",
  });
  if (creds.size)
    b.push({
      t: "table",
      head: ["Name", "Type", "Used in workflow(s)"],
      rows: [...creds.values()].map((c) => [c.name, c.type, c.wfs.join(", ")]),
    });
  else b.push({ t: "p", text: "None." });

  const envs = new Map();
  for (const { m } of items)
    for (const x of [
      ...m.env.env.map((n) => `$env.${n}`),
      ...m.env.vars.map((n) => `$vars.${n}`),
    ]) {
      if (!envs.has(x)) envs.set(x, []);
      envs.get(x).push(m.name);
    }
  b.push({
    t: "h",
    l: 2,
    text: "Environment variables and n8n variables to set",
  });
  if (envs.size)
    b.push({
      t: "table",
      head: ["Name", "Used in workflow(s)"],
      rows: [...envs].map(([k, v]) => [k, v.join(", ")]),
    });
  else b.push({ t: "p", text: "None." });

  const calls = [];
  for (const { m } of items)
    for (const s of m.subWorkflows)
      calls.push([m.name, s.node, s.name || "(not in this export)"]);
  b.push({ t: "h", l: 2, text: "Workflow-to-workflow calls" });
  if (calls.length)
    b.push({ t: "table", head: ["Caller", "Node", "Calls"], rows: calls });
  else b.push({ t: "p", text: "None." });

  const warn = items.filter(({ m }) => m.warnings.length);
  if (warn.length) {
    b.push({ t: "h", l: 2, text: "Needs attention before handover" });
    b.push({
      t: "ul",
      items: warn.flatMap(({ m }) => m.warnings.map((w) => `${m.name}: ${w}`)),
    });
  }
  return b;
}

module.exports = { workflowBlocks, indexBlocks, runbookRows };
