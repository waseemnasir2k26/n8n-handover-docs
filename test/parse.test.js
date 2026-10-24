"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeWorkflow } = require("../src/parse");
const { example, allExamples } = require("./helpers");

const byName = (m, n) => m.nodes.find((x) => x.name === n);
const nameOf = (m, id) => m.nodes.find((x) => x.id === id).name;
const edge = (m, a, b) =>
  m.edges.find((e) => nameOf(m, e.from) === a && nameOf(m, e.to) === b);

test("Schedule -> HTTP -> IF -> Gmail: connections, branch labels, schedule text", () => {
  const m = analyzeWorkflow(example("01-lead-alerts.json"));
  assert.equal(m.name, "Lead alerts (daily)");
  assert.equal(m.triggers[0].kind, "schedule");
  assert.match(
    m.triggers[0].schedule,
    /every 1 day\(s\) at 08:00 \(timezone Asia\/Makassar\)/,
  );
  assert.equal(edge(m, "Is it a hot lead?", "Email the owner").label, "true");
  assert.equal(
    edge(m, "Is it a hot lead?", "Add to nurture sheet").label,
    "false",
  );
  assert.equal(edge(m, "Every morning", "Fetch new leads").label, undefined);
  assert.deepEqual(m.order.map((id) => nameOf(m, id)).slice(0, 3), [
    "Every morning",
    "Fetch new leads",
    "Is it a hot lead?",
  ]);
  assert.deepEqual(m.services.map((s) => s.name).sort(), [
    "Gmail",
    "Google Sheets",
    "HTTP API (custom endpoint)",
  ]);
  assert.ok(m.env.env.includes("CRM_TENANT"));
  assert.equal(m.errorHandling.errorWorkflow.set, true);
  assert.equal(
    m.errorHandling.errorWorkflow.name,
    null,
    "name unknown when workflow is not in the set",
  );
  assert.match(m.errorHandling.retry[0], /Fetch new leads \(max 3 tries/);
  assert.ok(m.caps.some((c) => /timeout 15000/.test(c)));
  assert.equal(m.notes.length, 1);
});

test("error workflow name is resolved when the set contains it", () => {
  const all = allExamples();
  const idToName = new Map(all.map((w) => [w.id, w.name]));
  const m = analyzeWorkflow(example("01-lead-alerts.json"), { idToName });
  assert.equal(m.errorHandling.errorWorkflow.name, "Error alert");
});

test("Webhook -> AI Agent with sub-nodes: ai_* connections point sub-node -> agent", () => {
  const m = analyzeWorkflow(example("02-support-agent.json"), { showWebhookPaths: true });
  assert.equal(
    edge(m, "OpenAI Chat Model", "Support agent").type,
    "ai_languageModel",
  );
  assert.equal(edge(m, "OpenAI Chat Model", "Support agent").label, "model");
  assert.equal(edge(m, "Window memory", "Support agent").label, "memory");
  assert.equal(edge(m, "Look up order", "Support agent").label, "tool");
  assert.equal(byName(m, "OpenAI Chat Model").kind, "sub");
  assert.equal(byName(m, "Chat webhook").kind, "trigger");
  const a = m.agents[0];
  assert.equal(a.node, "Support agent");
  assert.deepEqual(a.parts.find((p) => p.label === "tool").names.sort(), [
    "Escalate to human",
    "Look up order",
  ]);
  assert.ok(
    m.services.some((s) => s.name === "Stripe"),
    "known API host is named",
  );
  assert.ok(m.services.some((s) => s.name === "OpenAI"));
  assert.equal(m.webhooks[0].method, "POST");
  assert.equal(m.webhooks[0].path, "support-chat");
  assert.equal(
    m.webhooks[0].url,
    "https://<your-n8n-host>/webhook/support-chat",
  );
  assert.ok(m.warnings.some((w) => /no authentication/.test(w)));
  assert.deepEqual(m.pinned, ["Chat webhook"]);
  assert.ok(m.warnings.some((w) => /Pinned/.test(w)));
  assert.equal(m.disabledCount, 1);
  assert.equal(m.secrets.length, 1);
  assert.equal(m.secrets[0].node, "Check Slack token");
  assert.ok(m.caps.some((c) => /iteration cap 6/.test(c)));
});

test("webhook host shown only with showHosts", () => {
  const wf = example("02-support-agent.json");
  const hidden = analyzeWorkflow(wf, { baseUrl: "https://n8n.example.test" });
  assert.ok(!hidden.webhooks[0].url.includes("n8n.example.test"));
  const shown = analyzeWorkflow(wf, {
    baseUrl: "https://n8n.example.test",
    showHosts: true,
    showWebhookPaths: true,
  });
  assert.equal(
    shown.webhooks[0].url,
    "https://n8n.example.test/webhook/support-chat",
  );
});

test("HTTP hosts hidden unless showHosts; known APIs named", () => {
  const wf = example("01-lead-alerts.json");
  const a = analyzeWorkflow(wf);
  assert.ok(!JSON.stringify(a).includes("example-client.test"));
  const b = analyzeWorkflow(wf, { showHosts: true });
  assert.ok(
    b.services.some((s) => s.name === "HTTP API: crm.example-client.test"),
  );
});

test("Execute Workflow sub-calls + Switch labels + error output branch", () => {
  const all = allExamples();
  const idToName = new Map(all.map((w) => [w.id, w.name]));
  const m = analyzeWorkflow(example("03-escalation.json"), { idToName });
  assert.equal(m.triggers[0].kind, "subworkflow");
  assert.equal(edge(m, "Route by urgency", "Page on-call").label, "urgent");
  assert.equal(
    edge(m, "Route by urgency", "Queue for morning").label,
    "normal",
  );
  assert.equal(edge(m, "Route by urgency", "Log unknown").label, "fallback");
  assert.equal(edge(m, "Page on-call", "Fallback email").label, "error");
  assert.deepEqual(m.errorHandling.errorOutputs, ["Page on-call"]);
  const caller = analyzeWorkflow(example("02-support-agent.json"), {
    idToName,
  });
  assert.deepEqual(
    caller.subWorkflows.map((s) => [s.node, s.name, s.viaTool]),
    [["Escalate to human", "Escalation to Slack", true]],
  );
});

test("executeWorkflow node resolves by id through the workflow set, never prints the id", () => {
  const wf = {
    name: "Caller",
    nodes: [
      {
        name: "Run child",
        type: "n8n-nodes-base.executeWorkflow",
        parameters: { workflowId: "child-id-123456" },
      },
    ],
    connections: {},
  };
  const m = analyzeWorkflow(wf, {
    idToName: new Map([["child-id-123456", "Child flow"]]),
  });
  assert.equal(m.subWorkflows[0].name, "Child flow");
  const lone = analyzeWorkflow(wf);
  assert.equal(lone.subWorkflows[0].name, null);
  assert.ok(!JSON.stringify(lone).includes("child-id-123456"));
});

test("Error Trigger workflow is recognised as an error workflow", () => {
  const m = analyzeWorkflow(example("04-error-alert.json"));
  assert.equal(m.errorHandling.isErrorWorkflow, true);
  assert.ok(!m.errorHandling.gaps.some((g) => /No error workflow/.test(g)));
  assert.ok(m.env.env.includes("ALERT_CHAT_ID"));
  assert.match(m.summary, /error handler/);
});

test("Cron / interval trigger shapes", () => {
  const cron = analyzeWorkflow({
    name: "c",
    nodes: [
      {
        name: "T",
        type: "n8n-nodes-base.cron",
        parameters: {
          triggerTimes: { item: [{ mode: "everyDay", hour: 7, minute: 30 }] },
        },
      },
    ],
    connections: {},
  });
  assert.match(cron.triggers[0].schedule, /every day at 07:30/);
  const expr = analyzeWorkflow({
    name: "c",
    nodes: [
      {
        name: "T",
        type: "n8n-nodes-base.scheduleTrigger",
        parameters: {
          rule: {
            interval: [{ field: "cronExpression", expression: "0 9 * * 1-5" }],
          },
        },
      },
    ],
    connections: {},
  });
  assert.match(expr.triggers[0].schedule, /cron 0 9 \* \* 1-5/);
});

test("loop calling an API without Wait is flagged", () => {
  const wf = {
    name: "loop",
    nodes: [
      {
        name: "Loop",
        type: "n8n-nodes-base.splitInBatches",
        typeVersion: 3,
        parameters: { batchSize: 10 },
      },
      {
        name: "Call",
        type: "n8n-nodes-base.slack",
        parameters: {},
        credentials: { slackApi: { id: "x", name: "S" } },
      },
    ],
    connections: {
      Loop: { main: [[], [{ node: "Call", type: "main", index: 0 }]] },
    },
  };
  const m = analyzeWorkflow(wf);
  assert.ok(m.caps.some((c) => /429/.test(c)));
  assert.equal(edge(m, "Loop", "Call").label, "loop");
});

test("tolerates n8n 2.x extras and malformed input without throwing", () => {
  const v2 = {
    ...example("01-lead-alerts.json"),
    versionId: "v",
    activeVersionId: "v",
    isArchived: false,
    shared: [{ role: "workflow:owner" }],
    meta: { templateCredsSetupCompleted: true },
    tags: ["plain-string-tag"],
  };
  const m = analyzeWorkflow(v2);
  assert.deepEqual(m.tags, ["plain-string-tag"]);
  for (const bad of [
    null,
    undefined,
    {},
    { nodes: null },
    { nodes: [null, 5, "x", {}], connections: "oops" },
    {
      nodes: [{ name: "A", type: 5 }],
      connections: { A: { main: [[{ node: "ghost" }], "x", null] }, ghost: {} },
    },
  ]) {
    assert.doesNotThrow(() => analyzeWorkflow(bad));
  }
  const empty = analyzeWorkflow({});
  assert.equal(empty.name, "Untitled workflow");
  assert.equal(empty.active, null);
});

test("credentials: names and types only, never ids", () => {
  const all = allExamples();
  for (const wf of all) {
    const m = analyzeWorkflow(wf);
    const s = JSON.stringify(m);
    for (const n of wf.nodes)
      for (const c of Object.values(n.credentials || {}))
        assert.ok(!s.includes(c.id), `credential id leaked: ${c.id}`);
    assert.ok(!s.includes(wf.id));
  }
  const m = analyzeWorkflow(example("01-lead-alerts.json"));
  assert.deepEqual(m.credentials.map((c) => [c.name, c.type]).sort(), [
    ["CRM API key", "httpHeaderAuth"],
    ["Owner Gmail", "gmailOAuth2"],
    ["Sheets (agency)", "googleSheetsOAuth2Api"],
  ]);
});

test('cron expressions get a plain-English reading, raw expression kept', () => {
  const { describeCron } = require('../src/cron');
  assert.equal(describeCron('0 15 7 * * *'), 'at 07:15, every day');
  assert.equal(describeCron('0 9 * * 1-5'), 'at 09:00, on weekdays');
  assert.equal(describeCron('*/15 * * * *'), 'every 15 minutes, every day');
  assert.equal(describeCron('0 */3 * * *'), 'every 3 hours at minute 0, every day');
  assert.equal(describeCron('30 8 * * 1,4'), 'at 08:30, on Monday, Thursday');
  assert.equal(describeCron('0 2,8,14,20 * * *'), 'at 02:00, 08:00, 14:00, 20:00, every day');
  assert.equal(describeCron('garbage'), null);
  assert.equal(describeCron(null), null);
  const m = analyzeWorkflow({ name: 'c', nodes: [{ name: 'T', type: 'n8n-nodes-base.scheduleTrigger', parameters: { rule: { interval: [{ field: 'cronExpression', expression: '0 9 * * 1-5' }] } } }], connections: {} });
  assert.match(m.triggers[0].schedule, /cron 0 9 \* \* 1-5 \(at 09:00, on weekdays\)/);
});
