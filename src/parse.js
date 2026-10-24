"use strict";
const {
  classify,
  classifyHost,
  shortType,
  titleFromCamel,
  typeLabel,
} = require("./rules");
const { findSecrets, redactContacts, collectEnvRefs } = require("./secrets");
const { sanitizeText, sanitizeIdent } = require("./policy");

// Every user-written string goes through the NAME POLICY (src/policy.js).
// Module state is set per analyzeWorkflow() call (the function is synchronous).
let HIDE_URLS = true;
let CONTACTS_ALL = false;
let CONTACTS_NOTES = true;
let COUNT = { names: 0 };
function hideUrls(s) {
  return HIDE_URLS ? s.replace(/\bhttps?:\/\/[^\s)"'`<>\]]+/gi, "<url hidden>") : s;
}
// Names (workflow, node, tag, credential, sub-workflow): normalise, then redact suspicious spans
function scrubText(t) {
  const s = hideUrls(sanitizeText(hideUrls(String(t == null ? "" : t)), { counters: COUNT }));
  return CONTACTS_ALL ? redactContacts(s) : s;
}
// Machine identifiers (node types, credential types, env var names): token rules only, no keyword rule
function scrubId(t) {
  return sanitizeIdent(t, { counters: COUNT });
}
// Sticky notes (only with --include-notes): same policy, longer, contacts hidden by default
function scrubNote(t) {
  const s = hideUrls(sanitizeText(hideUrls(String(t == null ? "" : t)), { kind: "note", maxLen: 600, counters: COUNT }));
  return CONTACTS_NOTES ? redactContacts(s) : s;
}
// Numbers and single words from parameters: nothing else may reach the output
const N = (v, d) => {
  const x = typeof v === "number" ? v : /^\d{1,9}$/.test(String(v)) ? Number(v) : NaN;
  return Number.isFinite(x) ? x : d;
};
const UNITS = new Set(["milliseconds", "seconds", "minutes", "hours", "days", "weeks", "months", "years", "second", "minute", "hour", "day", "week", "month", "year", "ms", "s", "m", "h", "d"]);
const W = (v, d) => (typeof v === "string" && UNITS.has(v.toLowerCase()) ? v : d);
// Fixed vocabularies only: nothing else from a parameter may reach the output
const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const pickMethod = (v, d) => { const m = String(v).toUpperCase(); return METHODS.has(m) ? m : d; };
const pickFrom = (v, list, d) => (typeof v === "string" && list.includes(v) ? v : d);
function word(v) {
  return String(v);
}
// Parameter paths: keep plain field names, hide anything that could carry a value
function safePath(path) {
  return String(path)
    .split(/([.[\]])/)
    .map((seg) => (/^[.[\]]$/.test(seg) || /^\d{1,4}$/.test(seg) || seg === "" ? seg : /^[A-Za-z][A-Za-z0-9]{0,30}$/.test(seg) && !/\d.*\d.*\d/.test(seg) ? seg : "*"))
    .join("");
}
// Webhook paths act as bearer tokens: show only a short prefix unless asked
function maskPath(path, show) {
  if (show || path.startsWith("(") || path.length <= 8) return path;
  return path.slice(0, 4) + "\u2026";
}
const { clean, trunc, uniq } = require("./util");
const { describeCron } = require("./cron");

function cronText(expr) {
  const raw = scrubText(plain(expr) || "(expression)");
  const d = plain(expr) && describeCron(expr);
  return `cron ${raw}${d ? ` (${d})` : ""}`;
}

const AI_LABELS = {
  ai_languageModel: "model",
  ai_tool: "tool",
  ai_memory: "memory",
  ai_embedding: "embeddings",
  ai_vectorStore: "vector store",
  ai_document: "documents",
  ai_textSplitter: "splitter",
  ai_outputParser: "parser",
  ai_retriever: "retriever",
  ai_reranker: "reranker",
};

const DAYS = [
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
];

const isStr = (v) => typeof v === "string";
const plain = (v) =>
  isStr(v) && !v.startsWith("=") && !/\{\{/.test(v) ? v : null;
const pad = (n) => String(N(n, 0)).padStart(2, "0");
const arr = (v) => (Array.isArray(v) ? v : []);
const obj = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : {});

function isTriggerType(short) {
  return (
    /trigger$/i.test(short) ||
    ["webhook", "cron", "interval", "start"].includes(short.toLowerCase())
  );
}

function describeSchedule(node, tz) {
  const p = obj(node.parameters);
  const short = shortType(node.type);
  const parts = [];
  if (short === "scheduleTrigger") {
    for (const it of arr(obj(p.rule).interval)) {
      const f = it && it.field;
      if (f === "cronExpression")
        parts.push(cronText(it.expression));
      else if (f === "seconds")
        parts.push(`every ${N(it.secondsInterval, 1)} second(s)`);
      else if (f === "minutes")
        parts.push(`every ${N(it.minutesInterval, 1)} minute(s)`);
      else if (f === "hours")
        parts.push(
          `every ${N(it.hoursInterval, 1)} hour(s) at minute ${pad(it.triggerAtMinute)}`,
        );
      else if (f === "days")
        parts.push(
          `every ${N(it.daysInterval, 1)} day(s) at ${pad(it.triggerAtHour)}:${pad(it.triggerAtMinute)}`,
        );
      else if (f === "weeks") {
        const d =
          arr(it.triggerAtDay)
            .map((x) => DAYS[x] || "")
            .join(", ") || "selected days";
        parts.push(
          `every ${N(it.weeksInterval, 1)} week(s) on ${d} at ${pad(it.triggerAtHour)}:${pad(it.triggerAtMinute)}`,
        );
      } else if (f === "months")
        parts.push(
          `every ${N(it.monthsInterval, 1)} month(s) on day ${N(it.triggerAtDayOfMonth, 1)} at ${pad(it.triggerAtHour)}:${pad(it.triggerAtMinute)}`,
        );
      else parts.push("custom interval");
    }
  } else if (short === "cron") {
    for (const it of arr(obj(p.triggerTimes).item)) {
      const m = it && it.mode;
      if (m === "everyMinute") parts.push("every minute");
      else if (m === "everyHour")
        parts.push(`every hour at minute ${pad(it.minute)}`);
      else if (m === "everyDay")
        parts.push(`every day at ${pad(it.hour)}:${pad(it.minute)}`);
      else if (m === "everyWeek")
        parts.push(
          `every ${DAYS[it.weekday] || "week"} at ${pad(it.hour)}:${pad(it.minute)}`,
        );
      else if (m === "everyMonth")
        parts.push(
          `monthly on day ${N(it.dayOfMonth, 1)} at ${pad(it.hour)}:${pad(it.minute)}`,
        );
      else if (m === "everyX")
        parts.push(`every ${N(it.value, 1)} ${W(it.unit, "unit")}`);
      else if (m === "custom")
        parts.push(
          cronText(it.cronExpression),
        );
    }
  } else if (short === "interval") {
    parts.push(`every ${N(p.interval, 1)} ${W(p.unit, "seconds")}`);
  }
  if (!parts.length) return null;
  return parts.join("; ") + (tz ? ` (timezone ${scrubText(tz)})` : "");
}

function hostOf(url) {
  if (!isStr(url)) return null;
  const s = url.startsWith("=") ? url.slice(1) : url;
  const m =
    /^\s*(?:\{\{[^}]*\}\}\s*)?https?:\/\/(?:[^/@\s]*@)?([A-Za-z0-9.-]{1,253})/i.exec(
      s,
    ) || /https?:\/\/(?:[^/@\s]*@)?([A-Za-z0-9.-]{3,253})/i.exec(s);
  return m ? m[1].toLowerCase() : null;
}

function conditionCount(p) {
  const c = obj(p.conditions);
  if (Array.isArray(c.conditions)) return c.conditions.length;
  return ["string", "number", "boolean", "dateTime"].reduce(
    (n, k) => n + arr(c[k]).length,
    0,
  );
}

function nodeDetail(node, ctx) {
  const p = obj(node.parameters);
  const short = shortType(node.type);
  const bits = [];
  if (short === "httpRequest" || short === "httpRequestTool") {
    bits.push(
      `${pickMethod(plain(p.method), "GET")} ${ctx.hostLabel(node)}`,
    );
  } else if (short === "code") {
    bits.push(
      `runs custom ${plain(p.language) === "python" || plain(p.language) === "pythonNative" ? "Python" : "JavaScript"} code`,
    );
  } else if (short === "set") {
    const n =
      arr(obj(p.assignments).assignments).length ||
      arr(obj(p.values).string).length;
    bits.push(n ? `sets ${n} field(s)` : "sets fields");
  } else if (short === "if") {
    bits.push(`checks ${conditionCount(p) || "a"} condition(s)`);
  } else if (short === "switch") {
    bits.push(
      `routes to ${arr(obj(p.rules).values).length || arr(obj(p.rules).rules).length || "several"} case(s)`,
    );
  } else if (short === "wait") {
    bits.push(
      `waits${p.amount ? ` ${N(p.amount, 0)} ${W(plain(p.unit), "")}` : ""}`.trim(),
    );
  } else if (short === "splitInBatches") {
    bits.push(`loops in batches of ${N(p.batchSize, "N")}`);
  } else {
    const r = plain(p.resource);
    const o = plain(p.operation);
    if (r || o) bits.push([r, o].filter(Boolean).join(" / "));
  }
  return scrubText(bits.join(" "));
}

function resolveWorkflowRef(ref, ctx) {
  // returns {name|null}
  if (ref == null) return { name: null };
  if (isStr(ref)) {
    const n = ctx.idToName.get(ref);
    return { name: n || null };
  }
  if (typeof ref === "object") {
    const v = ref.value;
    const n =
      (isStr(v) && ctx.idToName.get(v)) ||
      (isStr(ref.cachedResultName) ? ref.cachedResultName : null);
    return { name: n || null };
  }
  return { name: null };
}

/**
 * Turn one n8n workflow JSON object into a plain model. Reads only; never
 * copies credential ids, credential data, parameter values or pinned data.
 */
function analyzeWorkflow(wf, ctx = {}) {
  ctx = {
    idToName: ctx.idToName || new Map(),
    showHosts: !!ctx.showHosts,
    includeNotes: !!ctx.includeNotes,
    showWebhookPaths: !!ctx.showWebhookPaths,
    redactContacts: !!ctx.redactContacts,
    keepContacts: !!ctx.keepContacts,
    baseUrl: ctx.baseUrl || null,
  };
  HIDE_URLS = !ctx.showHosts;
  COUNT = { names: 0 };
  CONTACTS_ALL = !!ctx.redactContacts;
  CONTACTS_NOTES = ctx.keepContacts ? false : true;
  const warnings = [];
  const rawNodes = arr(wf && wf.nodes).filter(
    (n) => n && typeof n === "object",
  );
  const settings = obj(wf && wf.settings);
  const tz = /^[A-Za-z_\/+-]{1,40}$/.test(plain(settings.timezone) || "") ? plain(settings.timezone) : null;

  ctx.hostLabel = (node) => {
    const h = hostOf(obj(node.parameters).url);
    const known = h && classifyHost(h);
    if (known) return known.service;
    if (!h) return "a dynamic URL";
    return ctx.showHosts ? scrubId(h) : "a custom endpoint (host hidden)";
  };

  const nodes = [];
  const byName = new Map();
  rawNodes.forEach((n, i) => {
    const type = isStr(n.type) ? n.type : "unknown";
    const short = shortType(type);
    const name =
      scrubText(isStr(n.name) ? n.name : `Node ${i + 1}`) || `Node ${i + 1}`;
    const m = {
      id: `n${i}`,
      name,
      rawName: isStr(n.name) ? n.name : name,
      type: scrubId(type),
      short: scrubId(short),
      typeLabel: typeLabel(scrubId(short)),
      typeVersion: n.typeVersion,
      disabled: n.disabled === true,
      kind: "node",
      raw: n,
    };
    if (short === "stickyNote") m.kind = "note";
    else if (isTriggerType(short)) m.kind = "trigger";
    else if (short === "if" || short === "switch") m.kind = "branch";
    nodes.push(m);
    byName.set(m.rawName, m);
  });

  // ---- edges
  const edges = [];
  for (const [src, types] of Object.entries(obj(wf && wf.connections))) {
    const s = byName.get(src);
    if (!s) continue;
    for (const [ctype, outs] of Object.entries(obj(types))) {
      if (!Array.isArray(outs)) continue;
      outs.forEach((targets, outIdx) => {
        if (!Array.isArray(targets)) return;
        targets.forEach((t) => {
          const d = t && byName.get(t.node);
          if (d)
            edges.push({
              from: s.id,
              to: d.id,
              type: String(ctype),
              out: outIdx,
            });
        });
      });
    }
  }
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  for (const e of edges) if (e.type !== "main") nodeById.get(e.from).sub = true;
  for (const n of nodes) if (n.sub && n.kind !== "note") n.kind = "sub";

  // edge labels
  const mainOutCount = new Map();
  for (const e of edges)
    if (e.type === "main")
      mainOutCount.set(
        e.from,
        Math.max(mainOutCount.get(e.from) || 0, e.out + 1),
      );
  for (const e of edges) {
    const src = nodeById.get(e.from);
    const p = obj(src.raw.parameters);
    if (e.type !== "main") {
      e.label = AI_LABELS[e.type] || e.type.replace(/^ai_/, "");
      continue;
    }
    if (src.raw.onError === "continueErrorOutput" && e.out === 1) {
      e.label = "error";
      continue;
    }
    if (src.short === "if") e.label = e.out === 0 ? "true" : "false";
    else if (src.short === "switch") {
      const rules = arr(obj(p.rules).values);
      const r = rules[e.out];
      const key =
        r && isStr(r.outputKey) && r.outputKey ? scrubText(r.outputKey) : null;
      const fb =
        obj(p.options).fallbackOutput === "extra" && e.out === rules.length;
      e.label = fb ? "fallback" : key || `case ${e.out + 1}`;
    } else if (src.short === "splitInBatches" && Number(src.typeVersion) >= 3)
      e.label = e.out === 0 ? "done" : "loop";
    else if ((mainOutCount.get(e.from) || 0) > 1)
      e.label = `output ${e.out + 1}`;
  }

  // ---- services, credentials, env, secrets, webhooks, caps, errors
  const services = new Map();
  const credentials = new Map();
  const env = { env: new Set(), vars: new Set(), secrets: new Set() };
  const secrets = [];
  const webhooks = [];
  const caps = [];
  const subWorkflows = [];
  const retry = [];
  const continueOnFail = [];
  const errorOutputs = [];
  const triggers = [];
  const notes = [];
  let hiddenNotes = 0;
  const codeNodes = [];
  const agents = [];
  let hasLoop = false;
  let hasWait = false;
  let hasHttpBatching = false;
  let loopApiNodes = [];
  let disabledCount = 0;
  const externalNodes = [];

  const addService = (service, cat, nodeName, creds) => {
    if (!services.has(service))
      services.set(service, { name: service, cat, nodes: [], credentials: [] });
    const s = services.get(service);
    if (!s.nodes.includes(nodeName)) s.nodes.push(nodeName);
    for (const c of creds)
      if (!s.credentials.some((x) => x.type === c.type && x.name === c.name))
        s.credentials.push(c);
  };

  for (const n of nodes) {
    const raw = n.raw;
    const p = obj(raw.parameters);
    const creds = [];
    for (const [ctype, cv] of Object.entries(obj(raw.credentials))) {
      const c = obj(cv);
      const entry = {
        type: scrubId(ctype).slice(0, 80),
        name: scrubText(isStr(c.name) ? c.name : "(unnamed)").slice(0, 120),
      };
      creds.push(entry);
      const key = `${entry.type}\u0000${entry.name}`;
      if (!credentials.has(key)) credentials.set(key, { ...entry, nodes: [] });
      credentials.get(key).nodes.push(n.name);
    }
    if (n.disabled) {
      disabledCount++;
    }

    if (n.kind === "note") {
      hiddenNotes++;
      if (ctx.includeNotes) {
        const txt = scrubNote(plain(p.content) || "");
        if (txt) notes.push(trunc(txt, 600));
      }
      continue;
    }

    // env
    const refs = collectEnvRefs(p);
    refs.env.forEach((x) => env.env.add(x));
    refs.vars.forEach((x) => env.vars.add(x));
    refs.secrets.forEach((x) => env.secrets.add(x));
    // secrets
    for (const f of findSecrets(n.name, p))
      secrets.push({ ...f, path: safePath(f.path) });

    n.detail = nodeDetail(raw, ctx);
    if (n.disabled) continue;

    // service
    let cls = classify(
      raw.type,
      creds.map((c) => c.type),
    );
    if (cls && cls.derived) cls = { ...cls, service: scrubText(cls.service) };
    if (n.short === "httpRequest" || n.short === "httpRequestTool") {
      const h = hostOf(p.url);
      const known = h && classifyHost(h);
      if (known) cls = { service: known.service, cat: known.cat };
      else
        cls = {
          service:
            ctx.showHosts && h
              ? `HTTP API: ${scrubId(h)}`
              : "HTTP API (custom endpoint)",
          cat: "http",
        };
      if (
        isStr(p.url) &&
        /^=?\s*http:\/\//i.test(p.url) &&
        !/^=?\s*http:\/\/(localhost|127\.|\[::1\])/i.test(p.url)
      ) {
        warnings.push(
          `Node "${n.name}" calls a plain http:// URL (not encrypted).`,
        );
      }
      const b = obj(obj(obj(p.options).batching).batch);
      if (b.batchSize || b.batchInterval) {
        hasHttpBatching = true;
        caps.push(
          `"${n.name}": HTTP batching ${N(b.batchSize, "?")} per batch, ${N(b.batchInterval, 0)} ms between batches`,
        );
      }
      const to = obj(p.options).timeout;
      if (to) caps.push(`"${n.name}": request timeout ${N(to, 0)} ms`);
    }
    if (cls) {
      addService(cls.service, cls.cat, n.name, creds);
      n.service = cls.service;
      externalNodes.push(n);
    }

    // triggers
    if (n.kind === "trigger") {
      const sched = describeSchedule(raw, tz);
      let desc;
      if (["scheduleTrigger", "cron", "interval"].includes(n.short))
        desc = {
          kind: "schedule",
          text: sched
            ? `runs on a schedule: ${sched}`
            : "runs on a schedule (could not read the rule)",
          schedule: sched,
        };
      else if (n.short === "webhook")
        desc = { kind: "webhook", text: "receives an HTTP request (webhook)" };
      else if (n.short === "manualTrigger" || n.short === "start")
        desc = {
          kind: "manual",
          text: "can be run by hand",
          manual: true,
        };
      else if (n.short === "errorTrigger")
        desc = {
          kind: "error",
          text: "runs when another workflow fails (it is an error workflow)",
        };
      else if (n.short === "executeWorkflowTrigger")
        desc = { kind: "subworkflow", text: "is called by another workflow" };
      else if (n.short === "chatTrigger")
        desc = { kind: "chat", text: "starts when a chat message arrives" };
      else if (n.short === "formTrigger")
        desc = { kind: "form", text: "starts when a form is submitted" };
      else
        desc = {
          kind: "event",
          text: `starts on events from ${titleFromCamel(n.short) || n.short}`,
        };
      desc.node = n.name;
      desc.disabled = n.disabled;
      triggers.push(desc);
    }

    // webhooks
    if (
      n.short === "webhook" ||
      n.short === "formTrigger" ||
      n.short === "chatTrigger"
    ) {
      const path = maskPath(scrubText(plain(p.path) || plain(p.formPath) || (raw.webhookId ? "(auto-generated path)" : "(dynamic path)")), ctx.showWebhookPaths);
      const method =
        n.short === "webhook"
          ? (Array.isArray(p.httpMethod) ? p.httpMethod : [plain(p.httpMethod) || "GET"]).slice(0, 7).map((m) => pickMethod(m, "CUSTOM")).join("/")
          : n.short === "formTrigger"
            ? "GET/POST"
            : "POST";
      const auth = pickFrom(plain(p.authentication) || "none", ["none", "basicAuth", "headerAuth", "jwtAuth", "n8nUserAuth", "n8nAuth", "queryAuth"], "custom");
      const base =
        ctx.showHosts && ctx.baseUrl ? ctx.baseUrl : "https://<your-n8n-host>";
      const seg =
        n.short === "formTrigger"
          ? "form"
          : n.short === "chatTrigger"
            ? "webhook"
            : "webhook";
      webhooks.push({
        node: n.name,
        path,
        method: word(method),
        auth: word(auth),
        url: `${base}/${seg}/${path === "(auto-generated path)" ? "<id>" : path.replace(/^\//, "")}`,
        responseMode: pickFrom(plain(p.responseMode) || "onReceived", ["onReceived", "lastNode", "responseNode", "streaming", "formSubmitted"], "custom"),
      });
      if (auth === "none" && n.short === "webhook")
        warnings.push(
          `Webhook "${n.name}" has no authentication: anyone who knows the URL can trigger it.`,
        );
    }

    // sub-workflows
    if (n.short === "executeWorkflow" || n.short === "toolWorkflow") {
      const ref = p.workflowId !== undefined ? p.workflowId : p.workflow;
      const r = resolveWorkflowRef(ref, ctx);
      subWorkflows.push({
        node: n.name,
        name: r.name ? scrubText(r.name) : null,
        viaTool: n.short === "toolWorkflow",
      });
    }

    // loops / waits / caps
    if (n.short === "splitInBatches") {
      hasLoop = true;
      caps.push(
        `"${n.name}": processes items in batches of ${N(p.batchSize, "default size")}`,
      );
    }
    if (n.short === "wait") {
      hasWait = true;
      if (p.amount)
        caps.push(
          `"${n.name}": waits ${N(p.amount, 0)} ${W(plain(p.unit), "")}`.trim(),
        );
    }
    if (n.short === "limit")
      caps.push(`"${n.name}": keeps at most ${N(p.maxItems, 1)} item(s)`);
    if (n.short === "agent") {
      const mi = obj(p.options).maxIterations;
      caps.push(`"${n.name}": AI agent iteration cap ${N(mi, "default (10)")}`);
    }
    if (typeof p.limit === "number" && n.short !== "limit")
      caps.push(`"${n.name}": result limit ${N(p.limit, 0)}`);
    if (p.returnAll === true)
      caps.push(`"${n.name}": returns ALL results (no cap)`);
    if (n.short === "code") codeNodes.push(n.name);

    // per-node error handling
    if (raw.retryOnFail === true)
      retry.push(
        `${n.name} (max ${N(raw.maxTries, 3)} tries${raw.waitBetweenTries ? `, ${N(raw.waitBetweenTries, 0)} ms apart` : ""})`,
      );
    if (raw.continueOnFail === true || raw.onError === "continueRegularOutput")
      continueOnFail.push(n.name);
    if (raw.onError === "continueErrorOutput") errorOutputs.push(n.name);
  }

  // loop + external call without any wait/batching
  if (hasLoop && !hasWait && !hasHttpBatching) {
    loopApiNodes = externalNodes
      .filter((x) => x.service && x.service !== "Ollama (self-hosted)")
      .map((x) => x.name);
    if (loopApiNodes.length)
      caps.push(
        "This workflow loops over batches and calls external services without a Wait node or HTTP batching: a rate limit (429) is possible on large inputs.",
      );
  }
  if (Number(settings.executionTimeout) > 0)
    caps.push(`Workflow execution timeout: ${N(settings.executionTimeout, 0)} s`);

  // ---- steps (BFS from triggers over main edges), sub-nodes grouped under parent
  const mainOut = new Map();
  for (const e of edges)
    if (e.type === "main") {
      if (!mainOut.has(e.from)) mainOut.set(e.from, []);
      mainOut.get(e.from).push(e);
    }
  const order = [];
  const seen = new Set();
  const queue = nodes.filter((n) => n.kind === "trigger").map((n) => n.id);
  const visit = (start) => {
    const q = [start];
    while (q.length) {
      const id = q.shift();
      if (seen.has(id)) continue;
      seen.add(id);
      order.push(id);
      for (const e of mainOut.get(id) || []) q.push(e.to);
    }
  };
  queue.forEach(visit);
  nodes
    .filter((n) => n.kind === "node" || n.kind === "branch")
    .filter(
      (n) =>
        !seen.has(n.id) &&
        !edges.some((e) => e.type === "main" && e.to === n.id),
    )
    .forEach((n) => visit(n.id));
  nodes
    .filter(
      (n) =>
        (n.kind === "node" || n.kind === "branch" || n.kind === "trigger") &&
        !seen.has(n.id),
    )
    .forEach((n) => visit(n.id));
  const orphanSubs = nodes.filter((n) => n.kind === "sub");

  // ---- AI attachments
  const attach = new Map();
  for (const e of edges) {
    if (e.type === "main") continue;
    if (!attach.has(e.to)) attach.set(e.to, new Map());
    const m = attach.get(e.to);
    if (!m.has(e.label)) m.set(e.label, []);
    m.get(e.label).push(nodeById.get(e.from).name);
  }
  for (const [id, parts] of attach) {
    agents.push({
      node: nodeById.get(id).name,
      parts: [...parts].map(([label, names]) => ({ label, names })),
    });
  }

  // ---- pinned data (names only)
  const pinned = Object.keys(obj(wf && wf.pinData)).map((k) => scrubText(k));
  if (pinned.length)
    warnings.push(
      `Pinned (frozen) test data exists on ${pinned.length} node(s): ${pinned.join(", ")}. Pinned data replaces live output during manual test runs and can contain real customer data. Unpin before sharing the export.`,
    );
  if (secrets.length)
    warnings.push(
      `${secrets.length} possible hard-coded secret(s) found inside node parameters (listed by location, values masked). Move them to credentials or environment variables.`,
    );
  if (disabledCount)
    warnings.push(
      `${disabledCount} disabled node(s) are part of this workflow and are excluded from the service list.`,
    );

  // ---- error handling
  const isErrorWorkflow = triggers.some((t) => t.kind === "error");
  const ewRef = settings.errorWorkflow;
  let errorWorkflow = { set: false, name: null };
  if (isStr(ewRef) && ewRef) {
    const nm = ctx.idToName.get(ewRef);
    errorWorkflow = { set: true, name: nm ? scrubText(nm) : null };
  }
  const gaps = [];
  if (!isErrorWorkflow && !errorWorkflow.set)
    gaps.push(
      "No error workflow is set: a failure is visible only in the n8n Executions list.",
    );
  const unretried = externalNodes
    .filter((x) => x.raw.retryOnFail !== true)
    .map((x) => x.name);
  if (externalNodes.length && unretried.length === externalNodes.length)
    gaps.push(
      "No node that calls an external service has retry-on-fail enabled.",
    );
  const errorHandling = {
    errorWorkflow,
    isErrorWorkflow,
    retry,
    continueOnFail,
    errorOutputs,
    gaps,
  };

  // ---- credential totals
  const credList = [...credentials.values()].map((c) => ({
    ...c,
    nodes: uniq(c.nodes),
  }));

  // ---- id for lookup
  const meta = {
    name: scrubText(
      isStr(wf && wf.name) && wf.name ? wf.name : "Untitled workflow",
    ),
    active: typeof (wf && wf.active) === "boolean" ? wf.active : null,
    tags: arr(wf && wf.tags)
      .map((t) => scrubText(isStr(t) ? t : obj(t).name || ""))
      .filter(Boolean),
    nodeCount: nodes.filter((n) => n.kind !== "note").length,
  };

  const model = {
    ...meta,
    timezone: tz ? scrubText(tz) : null,
    nodes: nodes.map(({ raw, rawName, ...rest }) => rest),
    edges,
    order,
    orphanSubs: orphanSubs.map((n) => n.id),
    triggers,
    services: [...services.values()],
    credentials: credList,
    env: {
      env: [...env.env].sort(),
      vars: [...env.vars].sort(),
      secrets: [...env.secrets].sort(),
    },
    webhooks,
    errorHandling,
    caps: uniq(caps),
    subWorkflows,
    pinned,
    secrets,
    notes,
    codeNodes,
    agents,
    warnings,
    disabledCount,
  };
  model.env = { env: model.env.env.map(scrubId), vars: model.env.vars.map(scrubId), secrets: model.env.secrets.map(scrubId) };
  model.hiddenNotes = hiddenNotes;
  model.includeNotes = !!ctx.includeNotes;
  model.summary = plainSummary(model);
  model.redactedNames = COUNT.names;
  return model;
}

function listJoin(a) {
  if (a.length <= 1) return a.join("");
  return a.slice(0, -1).join(", ") + " and " + a[a.length - 1];
}

function plainSummary(m) {
  const out = [];
  const trig = m.triggers.filter((t) => !t.disabled);
  if (trig.length)
    out.push(`This workflow ${listJoin(trig.map((t) => (t.manual && trig.length === 1 ? "is started by hand (no automatic trigger)" : t.text)))}.`);
  else
    out.push(
      "This workflow has no trigger node, so it only runs when called or started by hand.",
    );
  const svc = m.services.map((s) => s.name);
  out.push(
    svc.length
      ? `Along the way it uses ${listJoin(svc)}.`
      : "It does not call any external service.",
  );
  const branches = m.nodes.filter((n) => n.kind === "branch" && !n.disabled);
  if (branches.length)
    out.push(
      `It makes decisions at ${listJoin(branches.map((b) => `"${b.name}"`))}.`,
    );
  for (const a of m.agents) {
    const bits = a.parts.map((p) => `${p.label}: ${p.names.join(", ")}`);
    out.push(`"${a.node}" is an AI step wired to ${bits.join("; ")}.`);
  }
  if (m.subWorkflows.length)
    out.push(`It hands work to ${m.subWorkflows.length} other workflow(s).`);
  if (m.errorHandling.isErrorWorkflow)
    out.push("It is an error handler for other workflows.");
  else if (m.errorHandling.errorWorkflow.set)
    out.push("When it fails, an error workflow is notified.");
  else out.push("If it fails, nothing is notified automatically.");
  return out.join(" ");
}

/** Pull plain structure for an LLM: node names, types, connections. Nothing else. */
function structureForLLM(m) {
  const byId = new Map(m.nodes.map((n) => [n.id, n]));
  return {
    workflow: m.name,
    nodes: m.nodes
      .filter((n) => n.kind !== "note")
      .map((n) => ({ name: n.name, type: n.short })),
    connections: m.edges.map((e) => ({
      from: byId.get(e.from).name,
      to: byId.get(e.to).name,
      kind: e.type,
      label: e.label || undefined,
    })),
  };
}

module.exports = { analyzeWorkflow, structureForLLM, hostOf, AI_LABELS };
