"use strict";
const fs = require("node:fs");
const path = require("node:path");

const EX = path.join(__dirname, "..", "examples", "workflows");

function example(name) {
  return JSON.parse(fs.readFileSync(path.join(EX, name), "utf8"));
}
function allExamples() {
  return fs
    .readdirSync(EX)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map(example);
}

// Fake secrets are assembled at runtime so no secret-looking literal sits in the repo.
const SECRETS = {
  openai: "sk-" + "Zq9xT".repeat(8),
  github: "ghp_" + "aB3dE".repeat(8),
  aws: "AKIA" + "QWERTYUIOPASDFGH",
  bearer: "Bearer " + "tK5vN".repeat(7),
  header: "hdr" + "Value9".repeat(5),
  assign: "pw" + "Secret7".repeat(3),
  url: "urlkey" + "Abc123".repeat(3),
};
const CRED_ID = "CREDID" + "x7Q2m9Zk4P";
const WF_ID = "WFID" + "a1B2c3D4e5F6";
const API_KEY =
  "eyJ" +
  "hbGciOiJIUzI1NiJ9".repeat(2) +
  "." +
  "payloadpayloadpayload" +
  "." +
  "sigsigsigsigsigsigsig";

function hostile() {
  return {
    id: WF_ID,
    name: 'Evil | name `x` <img src=x onerror=alert(1)> "q" [link](http://e.test)',
    active: true,
    settings: { errorWorkflow: "someErrorWorkflowId123" },
    pinData: {
      "Node A": [
        { json: { customer: "Jane Doe", email: "jane@example.test" } },
      ],
    },
    nodes: [
      {
        id: "1",
        name: "=cmd|' /C calc'!A0",
        type: "n8n-nodes-base.manualTrigger",
        typeVersion: 1,
        parameters: {},
      },
      {
        id: "2",
        name: "Node A",
        type: "n8n-nodes-base.httpRequest",
        typeVersion: 4.2,
        parameters: {
          method: "POST",
          url: `https://api.internal-client.test/v1/x?api_key=${SECRETS.url}`,
          sendHeaders: true,
          headerParameters: {
            parameters: [
              { name: "Authorization", value: SECRETS.bearer },
              { name: "X-Api-Key", value: SECRETS.header },
            ],
          },
          jsonBody: `={"token":"${SECRETS.assign}","ok":"{{ $env.SAFE_VAR }}"}`,
        },
        credentials: {
          httpHeaderAuth: { id: CRED_ID, name: 'Client "A" key' },
        },
      },
      {
        id: "3",
        name: 'Code "x"]\n--> evil',
        type: "n8n-nodes-base.code",
        typeVersion: 2,
        parameters: {
          jsCode: `const k = "${SECRETS.openai}"; const g = '${SECRETS.github}'; const a='${SECRETS.aws}'; return $vars.MY_VAR + $env["OTHER_VAR"];`,
        },
      },
      {
        id: "4",
        name: "__proto__",
        type: "n8n-nodes-base.noOp",
        typeVersion: 1,
        parameters: {},
      },
      {
        id: "5",
        name: "constructor",
        type: "n8n-nodes-base.noOp",
        typeVersion: 1,
        parameters: {},
      },
    ],
    connections: {
      "=cmd|' /C calc'!A0": {
        main: [[{ node: "Node A", type: "main", index: 0 }]],
      },
      "Node A": {
        main: [
          [
            { node: 'Code "x"]\n--> evil', type: "main", index: 0 },
            { node: "__proto__", type: "main", index: 0 },
          ],
        ],
      },
      ["__proto__"]: { main: [[{ node: "constructor", type: "main", index: 0 }]] },
    },
  };
}

module.exports = {
  example,
  allExamples,
  hostile,
  SECRETS,
  CRED_ID,
  WF_ID,
  API_KEY,
};
