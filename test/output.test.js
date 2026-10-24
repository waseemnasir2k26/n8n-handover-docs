"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { analyzeWorkflow } = require("../src/parse");
const { toMermaid, mLabel } = require("../src/mermaid");
const { generate } = require("../src/generate");
const { findSecrets } = require("../src/secrets");
const { sanitizeText } = require("../src/policy");
const { csvCell } = require("../src/util");
const { allExamples, hostile, SECRETS, CRED_ID, WF_ID } = require("./helpers");

// Small structural linter for the flowchart subset we emit.
function lintMermaid(src) {
  const lines = src.split("\n");
  assert.equal(lines[0], "flowchart TD");
  const ids = new Set();
  for (const l of lines.slice(1)) {
    let m;
    if (
      (m = /^ {2}(n\d+|empty)(\(\[|\{|\(|\[)"([^"]*)"(\]\)|\}|\)|\])$/.exec(l))
    ) {
      ids.add(m[1]);
      assert.ok(
        !/[<>&`\\|{}[\]()%;]/.test(
          m[3].replace(/<br\/>/g, "").replace(/#\d+;/g, ""),
        ),
        `unescaped char in label: ${l}`,
      );
    } else if ((m = /^ {2}(n\d+) (-->|-\.->)(\|"[^"]*"\|)? (n\d+)$/.exec(l))) {
      assert.ok(ids.has(m[1]) && ids.has(m[4]), `edge to unknown node: ${l}`);
    } else {
      assert.match(
        l,
        /^ {2}(classDef \w+ .+;|class [\w,]+ \w+;)$/,
        `unexpected line: ${JSON.stringify(l)}`,
      );
    }
  }
}

test("mermaid output is structurally valid for all examples and hostile names", () => {
  for (const wf of [...allExamples(), hostile()]) {
    const m = analyzeWorkflow(wf);
    lintMermaid(toMermaid(m));
  }
});

test("mermaid label escaping neutralises quotes, brackets, tags, arrows, comments", () => {
  const bad = 'a"b]c\n--> d %% e <script> `x` | {y} ; #z';
  const out = mLabel(bad);
  assert.ok(!/["<>`|{}\]\n;]/.test(out.replace(/#\d+;/g, "")));
  assert.ok(!out.includes("%%"));
  assert.ok(!out.includes("-->".replace(">", ">")) || out.includes("#62;"));
});

test("branches are labelled in mermaid text", () => {
  const m = analyzeWorkflow(allExamples()[0]);
  const src = toMermaid(m);
  assert.match(src, /-->\|"true"\|/);
  assert.match(src, /-->\|"false"\|/);
  const ag = toMermaid(analyzeWorkflow(allExamples()[1]));
  assert.match(ag, /-\.->\|"model"\|/);
  assert.match(ag, /-\.->\|"tool"\|/);
});

test("secret-pattern masking: location only, value never in the model", () => {
  const found = findSecrets("N", {
    a: SECRETS.openai,
    nested: { list: [`token ${SECRETS.github}`, SECRETS.aws] },
    headerParameters: {
      parameters: [{ name: "Authorization", value: SECRETS.bearer }],
    },
    ok1: "={{ $env.API_KEY }}",
    ok2: "your_api_key_here",
    password: "={{ $json.pw }}",
    url: "https://example.test/path",
  });
  const kinds = found.map((f) => f.path);
  assert.ok(kinds.includes("a"));
  assert.ok(kinds.some((k) => k.startsWith("nested.list[0]")));
  assert.ok(kinds.includes("nested.list[1]"));
  assert.ok(
    kinds.some((k) => k.includes("headerParameters.parameters[0].value")),
  );
  assert.ok(
    !kinds.includes("ok1") &&
      !kinds.includes("ok2") &&
      !kinds.includes("password") &&
      !kinds.includes("url"),
    "expressions and placeholders are not flagged",
  );
  const json = JSON.stringify(found);
  for (const v of Object.values(SECRETS))
    assert.ok(!json.includes(v), "secret value leaked into findings");
  assert.equal(sanitizeText(`x ${SECRETS.openai} y`), "x [redacted] y");
  assert.ok(!sanitizeText(`api_key="${SECRETS.assign}"`).includes(SECRETS.assign));
});

test("generated pack: no credential ids, workflow ids, secret values, or API key anywhere", async () => {
  const wf = hostile();
  const apiKey = "N8NKEY" + "q1w2e3r4t5y6u7";
  const sets = [...allExamples(), wf];
  const { files } = await generate(sets, {
    date: "2026-01-01",
    apiKey,
    showHosts: false,
  });
  const all = Object.values(files).join("\n");
  for (const v of Object.values(SECRETS))
    assert.ok(!all.includes(v), `secret leaked: ${v.slice(0, 6)}...`);
  assert.ok(!all.includes(CRED_ID));
  assert.ok(!all.includes(WF_ID));
  assert.ok(!all.includes(apiKey));
  for (const w of allExamples()) {
    assert.ok(!all.includes(w.id), "workflow id leaked");
    for (const n of w.nodes)
      for (const c of Object.values(n.credentials || {}))
        assert.ok(!all.includes(c.id), "credential id leaked");
  }
  assert.ok(!all.includes("internal-client.test"), "hidden host leaked");
  assert.ok(
    !all.includes("jane@example.test") && !all.includes("Jane Doe"),
    "pinned data leaked",
  );
  assert.match(all, /\[masked, \d+ chars\]/);
});

test("backstop strips an id even if it reaches a free-text field", async () => {
  const wf = {
    id: WF_ID,
    name: `Report for ${WF_ID}`,
    nodes: [],
    connections: {},
  };
  const { files, warnings } = await generate([wf], { date: "2026-01-01" });
  assert.ok(!Object.values(files).join("").includes(WF_ID));
  assert.ok(Array.isArray(warnings));
});

test("HTML: everything from workflow JSON is escaped; CSP present; CDN pinned with SRI", async () => {
  const { files } = await generate([hostile()], { date: "2026-01-01" });
  const html = files["index.html"];
  assert.ok(!html.includes("<img src=x"), "raw tag from workflow name");
  assert.ok(!/<script>alert/.test(html));
  assert.match(html, /&lt;img src=x/);
  assert.match(html, /Content-Security-Policy/);
  assert.match(
    html,
    /mermaid@\d+\.\d+\.\d+\/dist\/mermaid\.min\.js" integrity="sha384-/,
  );
  assert.equal((html.match(/<script/g) || []).length, 3 - 1 /* src + inline */);
  const off = (
    await generate([hostile()], { date: "2026-01-01", offline: true })
  ).files["index.html"];
  assert.ok(!/<script/.test(off));
  assert.match(off, /Diagram shown as text: --offline was used/);
  assert.match(html, /@media print/);
});

test("Markdown: pipes, backticks, html and links in names cannot break tables", async () => {
  const { files } = await generate([hostile()], { date: "2026-01-01" });
  const md = Object.entries(files).find(
    ([k]) => k.endsWith(".md") && k !== "index.md",
  )[1];
  assert.ok(!md.includes("<img"));
  assert.ok(!/\[link\]\(http/.test(md), "markdown link injection");
  const fences = md.match(/```/g) || [];
  assert.equal(fences.length % 2, 0);
  for (const line of md.split("\n").filter((l) => l.startsWith("|"))) {
    const cells = line.replace(/\\\|/g, "").split("|").length;
    assert.ok(cells >= 3);
  }
});

test("CSV: formula injection neutralised, quoting correct", async () => {
  assert.equal(csvCell("=SUM(A1)"), '"\'=SUM(A1)"');
  assert.equal(csvCell("+1"), '"\'+1"');
  assert.equal(csvCell("-2"), '"\'-2"');
  assert.equal(csvCell("@x"), '"\'@x"');
  assert.equal(csvCell(" =x"), '"\' =x"');
  assert.equal(csvCell('a"b,c'), '"a""b,c"');
  const wf = {
    name: '=HYPERLINK("http://e.test")',
    nodes: [
      {
        name: "n",
        type: "n8n-nodes-base.slack",
        parameters: {},
        credentials: { slackApi: { id: "zzzzzzzz1", name: "+cmd" } },
      },
    ],
    connections: {},
  };
  const { files } = await generate([wf], { date: "2026-01-01" });
  for (const row of files["inventory.csv"].trim().split("\r\n").slice(1)) {
    for (const cell of row.match(/"(?:[^"]|"")*"/g))
      assert.ok(!/^"[=+\-@]/.test(cell), `unsafe cell ${cell}`);
  }
  assert.equal(
    files["inventory.csv"].split("\r\n")[0],
    '"workflow","active","service","credential_name","credential_type","nodes"',
  );
});

test("prototype-pollution-ish node names do not break anything", () => {
  const m = analyzeWorkflow(hostile());
  assert.ok(m.nodes.some((n) => n.name === "proto"));
  assert.ok(m.edges.some((e) => nameOf(m, e.from) === "proto"));
  assert.equal({}.polluted, undefined);
  function nameOf(mm, id) {
    return mm.nodes.find((x) => x.id === id).name;
  }
});

test("file names are safe slugs and unique", async () => {
  const wfs = [
    { name: "../../etc/passwd", nodes: [], connections: {} },
    { name: "../../etc/passwd", nodes: [], connections: {} },
    { name: "index", nodes: [], connections: {} },
    { name: "", nodes: [], connections: {} },
  ];
  const { files } = await generate(wfs, { date: "2026-01-01" });
  const names = Object.keys(files);
  for (const n of names) assert.match(n, /^[a-z0-9][a-z0-9.-]*$/);
  assert.equal(new Set(names).size, names.length);
});

test("runbook lists per service failures and where to look (node names)", async () => {
  const { files } = await generate(allExamples(), { date: "2026-01-01" });
  const md = files["lead-alerts-daily.md"];
  assert.match(md, /### When it breaks/);
  assert.match(md, /Gmail \| Auth expired or revoked/);
  assert.match(md, /Node\(s\): Email the owner/);
  assert.match(md, /429/);
});

test("write to disk", async () => {
  const { writeFiles } = require("../src/generate");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hand-"));
  const { files } = await generate(allExamples(), { date: "2026-01-01" });
  writeFiles(dir, files);
  assert.ok(fs.existsSync(path.join(dir, "index.html")));
  assert.throws(() => writeFiles(dir, { "../x.md": "x" }));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('HTML diagram block keeps line breaks and equals the Markdown diagram source', async () => {
  const { files } = await generate(allExamples(), { date: '2026-01-01' });
  const html = files['index.html'];
  const un = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
  const blocks = [...html.matchAll(/<pre class="mermaid">([\s\S]*?)<\/pre>/g)].map((m) => un(m[1]));
  assert.equal(blocks.length, 5);
  const md = files['lead-alerts-daily.md'];
  const mdSrc = /```mermaid\n([\s\S]*?)```/.exec(md)[1];
  assert.ok(blocks.some((b) => b.trim() === mdSrc.trim()));
  for (const b of blocks) assert.ok(b.startsWith('flowchart TD\n'));
});

test('URLs inside names and sticky notes are hidden unless --show-hosts', () => {
  const wf = { name: 'W https://client.example.test/x', nodes: [{ name: 'Note', type: 'n8n-nodes-base.stickyNote', parameters: { content: 'See https://internal-host.example.test/docs for details' } }], connections: {} };
  const hidden = JSON.stringify(analyzeWorkflow(wf, { includeNotes: true }));
  assert.ok(!hidden.includes('example.test'));
  assert.ok(hidden.includes('<url hidden>'));
  const shown = JSON.stringify(analyzeWorkflow(wf, { showHosts: true, includeNotes: true }));
  assert.ok(shown.includes('internal-host.example.test'));
});
