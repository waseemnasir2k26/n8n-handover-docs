"use strict";
// Adversarial corpus: hostile secrets (homoglyphs, zero-width, fullwidth, markdown/table/entity
// wrappers, newline between key and value, natural language, URL-encoded, base64, split keys, ...)
// planted in every field of a workflow that could reach the pack. Fake values are assembled at
// runtime so no secret-looking literal sits in the repo.

const b64 = Buffer.from("sk-proj-" + "ABCDEFGH12345678ZZZZ").toString("base64");
const AWS = "AKIA" + "IOSFODNN7EXAMPLE";
const GH = "ghp_" + "aB3dE9".repeat(6);

const SECRETS = {
  split: ["password:\nQx7!vTz9mK2p", "the password\nis\nHorseBattery9!"],
  pw_words: [
    "my password is correct horse battery staple",
    "pass: Zq8wRt5Yu",
    "login pw = Tr0ub4dor&3",
  ],
  b64: ["key: " + b64, "c2stcHJvai1BQkNERUZHSDEyMzQ1Njc4Wlpa"],
  urlenc: ["api_key%3D" + "SUPERSECRET" + "VALUE99", "token%3D" + "abcd1234" + "efgh5678"],
  expr: [
    '={{ "sk-ABCDEFGHIJKLMNOPQRSTUV123" }}',
    '{{ "hunter2hunter2xyz" }} is the password',
  ],
  cyr: ["pаssword: Winter2026!!", "рassword = Spring2027##x"],
  codejson: [
    'const b = JSON.stringify({"pass word":"zzTop12345!"}); const x={"db_pwd":"Abcdef123456"}; const cfg = "user:Sup3rS3cretPw@host"',
  ],
  other: [
    GH,
    "Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==",
    "postgres://admin:Pa55w0rd!@db.example.com/x",
    AWS,
    "s e c r e t: abc12345XYZ",
    "pass-phrase: correct-horse-9",
  ],
  spaced: [
    "API KEY: " + "8f3a9c1d" + "2e7b4a60",
    "api key is " + "8f3a9c1d" + "2e7b4a60",
    "passcode: 482910",
    "PIN is 482910 secret",
    "credentials: admin / Xk29!mm22",
  ],
};

const BASE = () => ({
  id: "wfid0abcdef",
  name: "WF",
  active: false,
  nodes: [
    {
      id: "1",
      name: "Start",
      type: "n8n-nodes-base.manualTrigger",
      typeVersion: 1,
      position: [0, 0],
      parameters: {},
    },
    {
      id: "2",
      name: "Do",
      type: "n8n-nodes-base.set",
      typeVersion: 1,
      position: [200, 0],
      parameters: {},
    },
  ],
  connections: { Start: { main: [[{ node: "Do", type: "main", index: 0 }]] } },
  settings: {},
  tags: [],
  pinData: {},
});
const nl = (v) => v.replace(/\n/g, " ");

const FIELDS = {
  sticky: (w, v) =>
    w.nodes.push({
      id: "3",
      name: "Sticky Note",
      type: "n8n-nodes-base.stickyNote",
      typeVersion: 1,
      position: [0, 200],
      parameters: { content: v, height: 100, width: 200 },
    }),
  sticky2: (w, v) =>
    w.nodes.push({
      id: "3",
      name: "Note",
      type: "n8n-nodes-base.stickyNote",
      typeVersion: 1,
      position: [0, 200],
      parameters: { content: "# Title\n\n- item\n" + v + "\n\n> quote" },
    }),
  nodename: (w, v) => {
    w.nodes[1].name = "Call " + nl(v);
  },
  wfname: (w, v) => {
    w.name = "Flow " + nl(v);
  },
  tag: (w, v) => {
    w.tags = [{ id: "t1", name: nl(v) }];
  },
  credname: (w, v) => {
    w.nodes[1].credentials = {
      httpHeaderAuth: { id: "cid123456", name: nl(v) },
    };
  },
  credtype: (w, v) => {
    w.nodes[1].credentials = {
      [nl(v).slice(0, 60)]: { id: "cid123456", name: "x" },
    };
  },
  nodetype: (w, v) => {
    w.nodes[1].type = "n8n-nodes-base." + nl(v).slice(0, 60);
  },
  notes: (w, v) => {
    w.nodes[1].notes = v;
    w.nodes[1].notesInFlow = true;
  },
  desc: (w, v) => {
    w.nodes[1].parameters.description = v;
  },
  pin: (w, v) => {
    w.pinData = { Do: [{ json: { msg: v } }] };
  },
  pinkey: (w, v) => {
    w.pinData = { [nl(v)]: [{ json: { a: 1 } }] };
  },
  settings: (w, v) => {
    w.settings = { errorWorkflow: "x", timezone: "UTC", callerPolicy: nl(v) };
  },
  tz: (w, v) => {
    w.settings = { timezone: nl(v) };
  },
  codejs: (w, v) => {
    w.nodes[1].type = "n8n-nodes-base.code";
    w.nodes[1].parameters = { jsCode: "// " + v + "\nreturn items;" };
  },
  codejs2: (w, v) => {
    w.nodes[1].type = "n8n-nodes-base.code";
    w.nodes[1].parameters = { jsCode: "const a = `" + v + "`;\nreturn items;" };
  },
  httpbody: (w, v) => {
    w.nodes[1].type = "n8n-nodes-base.httpRequest";
    w.nodes[1].parameters = { url: "https://api.example.com/x", jsonBody: v };
  },
  httpurl: (w, v) => {
    w.nodes[1].type = "n8n-nodes-base.httpRequest";
    w.nodes[1].parameters = { url: nl(v), method: nl(v) };
  },
  setval: (w, v) => {
    w.nodes[1].parameters = {
      values: { string: [{ name: "note", value: v }] },
    };
  },
  setkey: (w, v) => {
    w.nodes[1].parameters = {
      values: { string: [{ name: nl(v), value: "x" }] },
      [nl(v)]: "x",
    };
  },
  opname: (w, v) => {
    w.nodes[1].parameters = { operation: nl(v), resource: nl(v) };
  },
  webhook: (w, v) => {
    w.nodes[0] = {
      id: "1",
      name: "Start",
      type: "n8n-nodes-base.webhook",
      typeVersion: 1,
      position: [0, 0],
      webhookId: "w",
      parameters: {
        path: nl(v),
        httpMethod: nl(v),
        authentication: nl(v),
        responseMode: nl(v),
      },
    };
  },
  schedule: (w, v) => {
    w.nodes[0] = {
      id: "1",
      name: "Start",
      type: "n8n-nodes-base.scheduleTrigger",
      typeVersion: 1,
      position: [0, 0],
      parameters: {
        rule: {
          interval: [
            {
              field: nl(v),
              hoursInterval: nl(v),
              triggerAtMinute: nl(v),
              expression: nl(v),
            },
          ],
        },
      },
    };
  },
  caps: (w, v) => {
    w.nodes[1].type = "n8n-nodes-base.splitInBatches";
    w.nodes[1].parameters = {
      batchSize: nl(v),
      maxItems: nl(v),
      amount: nl(v),
      unit: nl(v),
    };
    w.nodes[1].retryOnFail = true;
    w.nodes[1].maxTries = nl(v);
    w.settings = { executionTimeout: nl(v) };
  },
  envref: (w, v) => {
    w.nodes[1].parameters = {
      x:
        '={{ $env["' +
        nl(v) +
        '"] }} {{ $vars.' +
        nl(v).replace(/\W/g, "_") +
        " }}",
    };
  },
  subwf: (w, v) => {
    w.nodes[1].type = "n8n-nodes-base.executeWorkflow";
    w.nodes[1].parameters = {
      workflowId: { __rl: true, value: "abc", cachedResultName: nl(v) },
    };
  },
  outkey: (w, v) => {
    w.nodes[1].type = "n8n-nodes-base.switch";
    w.nodes[1].parameters = { rules: { values: [{ outputKey: nl(v) }] } };
    w.nodes.push({
      id: "9",
      name: "Out",
      type: "n8n-nodes-base.noOp",
      parameters: {},
    });
    w.connections.Do = { main: [[{ node: "Out", type: "main", index: 0 }]] };
  },
};

// Judge A + C extra cases (each: [text, distinctive token that must not appear])
const EXTRA = {
  zwsp: ["pass​word: Winter2026!!", "Winter2026!!"],
  fullwidth: ["ｐassword: Winter2026!!", "Winter2026!!"],
  split_nl: ["password:\nWinter2026!!", "Winter2026!!"],
  split_nl2: ["the password is\n\n  Winter2026!!", "Winter2026!!"],
  nl_after_kw: ["Password\nWinter2026!!x", "Winter2026!!x"],
  md_bold: ["**password**: Winter2026!!", "Winter2026!!"],
  md_table: ["| password | Winter2026!! |", "Winter2026!!"],
  html_ent: ["password&#58; Winter2026!!", "Winter2026!!"],
  pwd_cap: ["PW: Winter2026!!", "Winter2026!!"],
  shortval: ["password: abc12", "abc12"],
  quoted_space: ['password: "my winter pass"', "winter pass"],
  pw_space: ["password: Winter 2026!!", "2026!!"],
  passw_is: ["The password for the CRM is Winter2026!!", "Winter2026!!"],
  login: ["Login: bob@x.com / Winter2026!!", "Winter2026!!"],
  b64key: [
    "Zm9vYmFyOnN1cGVyc2VjcmV0cGFzc3dvcmQ=",
    "c3VwZXJzZWNyZXRwYXNzd29yZA",
  ],
  sk_split: ["sk-proj-ABCDEFGH\n12345678ZZZZ9999", "12345678ZZZZ9999"],
  sk_dash: ["sk- ABCDEFGHIJKLMNOPQRSTUV12", "ABCDEFGHIJKLMNOPQRSTUV12"],
  hex40: [
    "a3f5c9d2e1b04a7788c6d5e4f3a2b1c0d9e8f7a6",
    "a3f5c9d2e1b04a7788c6d5e4f3a2b1c0",
  ],
  long100k: ["x ".repeat(50000) + " password: Winter2026!!", "Winter2026!!"],
  long_kw: ["password: " + "A1".repeat(150), "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1"],
  rotated: ["drowssap: Winter2026!!", "Winter2026!!"],
  camel: ["dbPassword Winter2026!!", "Winter2026!!"],
  hdr_x: ["X-Api-Key Winter2026!!abc", "Winter2026!!abc"],
  leet: ["p4ssw0rd: Winter2026!!", "Winter2026!!"],
  spaced_letters: ["p a s s w o r d : Winter2026!!", "Winter2026!!"],
  pct_kw: ["pass%77ord%3A%20Winter2026!!", "Winter2026!!"],
  entity_kw: ["&#112;assword&colon; Winter2026!!", "Winter2026!!"],
  greek: ["ραssword: Winter2026!!", "Winter2026!!"],
};
const EXTRA_FIELDS = ["sticky", "nodename", "wfname", "tag", "credname"];

function tokensOf(s) {
  return (s.match(/[A-Za-z0-9!&#%@_+=/.-]{8,}/g) || []).filter(
    (t) => /\d|[!#&]/.test(t) || t.length >= 20,
  );
}

function* cases() {
  for (const [g, arr] of Object.entries(SECRETS)) {
    for (const s of arr) {
      for (const [f, fn] of Object.entries(FIELDS)) {
        const wf = BASE();
        fn(wf, s);
        // tokens that would prove a leak
        yield {
          id: `${g}/${f}`,
          group: g,
          field: f,
          wf,
          tokens: tokensOf(s),
          sticky: f.startsWith("sticky"),
        };
      }
    }
  }
  for (const [k, [s, tok]] of Object.entries(EXTRA)) {
    for (const f of EXTRA_FIELDS) {
      const wf = BASE();
      FIELDS[f](wf, s);
      yield {
        id: `extra:${k}/${f}`,
        group: k,
        field: f,
        wf,
        tokens: [tok],
        sticky: f === "sticky",
      };
    }
  }
  // Judge A's mixed hostile workflow
  const hostile = {
    id: "WFID123abc",
    name: "Sync https://user:Sup3rSecret@db.example.com/x",
    active: true,
    tags: [{ name: "pass​word: hunter2hunter2" }],
    settings: { errorWorkflow: "X", callerPolicy: "any" },
    meta: { instanceId: "INSTANCEID9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c" },
    nodes: [
      {
        id: "1",
        name: "Hook <img src=x onerror=alert(1)>",
        type: "n8n-nodes-base.webhook",
        typeVersion: 1,
        position: [0, 0],
        parameters: { path: "abcd-SECRETPATHtail9", httpMethod: "POST" },
        webhookId: "wh-1234-5678",
      },
      {
        id: "2",
        name: "Note node",
        type: "n8n-nodes-base.set",
        typeVersion: 1,
        position: [200, 0],
        notes: "use passphrase correcthorsebatterystaple",
        parameters: { values: { string: [{ name: "k", value: "x" }] } },
      },
      {
        id: "3",
        name: "Sticky",
        type: "n8n-nodes-base.stickyNote",
        typeVersion: 1,
        position: [0, 200],
        parameters: {
          content:
            "## creds\nlogin: admin / Tr0ub4dor&3\nconnection string postgres://admin:Tr0ub4dor3@10.0.0.5/db\nkey (base64): c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0\nAPI KEY → " + "sk_" + "live_abcdefghij" + "klmnopqrstu" + "\n[click](javascript:alert(1)) <script>alert(1)</script> ![x](http://evil.example/p.png?d=1)",
        },
      },
      {
        id: "4",
        name: "=cmd|' /C calc'!A0",
        type: "n8n-nodes-base.httpRequest",
        typeVersion: 4,
        position: [400, 0],
        credentials: {
          httpHeaderAuth: { id: "CRED777", name: '=HYPERLINK("http://evil")' },
        },
        parameters: {
          url: "https://api.example.com/v1?apikey=" + "abcdEFGH" + "12345678",
          method: "GET",
        },
      },
    ],
    connections: {
      "Hook <img src=x onerror=alert(1)>": {
        main: [[{ node: "Note node", type: "main", index: 0 }]],
      },
    },
    pinData: { "Note node": [{ json: { ssn: "123-45-6789" } }] },
  };
  yield {
    id: "judgeA/hostile",
    group: "judgeA",
    field: "mixed",
    wf: hostile,
    sticky: true,
    tokens: [
      "hunter2hunter2",
      "Sup3rSecret",
      "Tr0ub4dor",
      "correcthorsebatterystaple",
      "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0",
      "sk_" + "live_abcdefghij" + "klmnopqrstu",
      "abcdEFGH12345678",
      "SECRETPATHtail9",
      "INSTANCEID9f8e7d6c",
      "123-45-6789",
      "WFID123abc",
      "CRED777",
    ],
  };
}

module.exports = { cases, SECRETS, FIELDS, EXTRA };
