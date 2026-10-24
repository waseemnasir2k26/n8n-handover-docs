'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { fetchWorkflows, normaliseBase } = require('../src/api');
const { main } = require('../src/cli');
const { summarize, buildPrompt } = require('../src/llm');
const { analyzeWorkflow } = require('../src/parse');
const { allExamples, hostile, API_KEY, SECRETS, CRED_ID } = require('./helpers');

const json = (body, status = 200) => ({ status, ok: status >= 200 && status < 300, json: async () => body });

test('API: GET only, key in one header, redirect manual, never in URL', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return json({ data: [{ name: 'w', nodes: [], connections: {} }] });
  };
  const out = await fetchWorkflows({ baseUrl: 'https://n8n.example.test/', apiKey: API_KEY, tag: 'client-x', activeOnly: true, fetchImpl });
  assert.equal(out.length, 1);
  const { url, init } = calls[0];
  assert.equal(init.method, 'GET');
  assert.equal(init.redirect, 'manual');
  assert.equal(init.headers['X-N8N-API-KEY'], API_KEY);
  assert.ok(!url.includes(API_KEY));
  assert.match(url, /^https:\/\/n8n\.example\.test\/api\/v1\/workflows\?/);
  assert.match(url, /tags=client-x/);
  assert.match(url, /active=true/);
  assert.equal(init.body, undefined);
});

test('API: pagination follows nextCursor and honours limit', async () => {
  let n = 0;
  const fetchImpl = async (url) => {
    n++;
    const cursor = new URL(url).searchParams.get('cursor');
    return json({ data: [{ name: `p${n}`, nodes: [] }, { name: `q${n}`, nodes: [] }], nextCursor: cursor ? null : 'c2' });
  };
  assert.equal((await fetchWorkflows({ baseUrl: 'https://x.test', apiKey: 'k'.repeat(10), fetchImpl })).length, 4);
  n = 0;
  assert.equal((await fetchWorkflows({ baseUrl: 'https://x.test', apiKey: 'k'.repeat(10), limit: 3, fetchImpl })).length, 3);
});

test('API: a redirect is refused and the key is not in the error', async () => {
  const fetchImpl = async () => ({ status: 302, ok: false, headers: { get: () => 'https://evil.test/' }, json: async () => ({}) });
  await assert.rejects(fetchWorkflows({ baseUrl: 'https://x.test', apiKey: API_KEY, fetchImpl }), (e) => {
    assert.match(e.message, /redirect/);
    assert.ok(!e.message.includes(API_KEY));
    assert.ok(!e.message.includes('evil.test'));
    return true;
  });
});

test('API: errors never contain the key; 401 and 500 handled; bad base urls rejected', async () => {
  const leaky = async () => { throw new Error(`boom ${API_KEY}`); };
  await assert.rejects(fetchWorkflows({ baseUrl: 'https://x.test', apiKey: API_KEY, fetchImpl: leaky }), (e) => !e.message.includes(API_KEY));
  await assert.rejects(fetchWorkflows({ baseUrl: 'https://x.test', apiKey: API_KEY, fetchImpl: async () => json({}, 401) }), /refused the key/);
  await assert.rejects(fetchWorkflows({ baseUrl: 'https://x.test', apiKey: API_KEY, fetchImpl: async () => json({}, 500) }), /HTTP 500/);
  await assert.rejects(fetchWorkflows({ baseUrl: 'https://x.test', apiKey: API_KEY, fetchImpl: async () => json({ nope: 1 }) }), /Unexpected/);
  await assert.rejects(fetchWorkflows({ baseUrl: 'https://x.test', apiKey: '' , fetchImpl: async () => json({}) }), /N8N_API_KEY/);
  assert.throws(() => normaliseBase('http://n8n.example.test'), /https/);
  assert.throws(() => normaliseBase('https://user:pw@n8n.example.test'), /username/);
  assert.throws(() => normaliseBase('not a url'), /valid URL/);
  assert.equal(normaliseBase('http://localhost:5678'), 'http://localhost:5678');
  assert.equal(normaliseBase('https://n8n.example.test/api/v1/'), 'https://n8n.example.test');
});

function capture() {
  const o = []; const e = [];
  return { o, e, io: { out: (s) => o.push(s), err: (s) => e.push(s) } };
}

test('CLI --live: writes a pack, key and ids absent from stdout, stderr and files', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'live-'));
  const c = capture();
  const wfs = [...allExamples(), hostile()].map((w, i) => ({ ...w, tags: [{ name: 'client-x' }], id: w.id || `id-${i}-aaaaaaaa` }));
  c.io.fetchImpl = async () => json({ data: wfs });
  const code = await main(['--live', '--tag', 'Client-X', '--out', dir, '--date', '2026-01-01'], { N8N_BASE_URL: 'https://n8n.example.test', N8N_API_KEY: API_KEY }, c.io);
  assert.equal(code, 0);
  const files = fs.readdirSync(dir);
  assert.ok(files.includes('index.html') && files.includes('inventory.csv'));
  const all = files.map((f) => fs.readFileSync(path.join(dir, f), 'utf8')).join('\n') + c.o.join('\n') + c.e.join('\n');
  assert.ok(!all.includes(API_KEY));
  assert.ok(!all.includes('n8n.example.test'), 'host must stay hidden without --show-hosts');
  assert.ok(!all.includes(CRED_ID));
  for (const v of Object.values(SECRETS)) assert.ok(!all.includes(v));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CLI --live failure paths print no key; wrong flags exit 2', async () => {
  const env = { N8N_BASE_URL: 'https://n8n.example.test', N8N_API_KEY: API_KEY };
  let c = capture();
  c.io.fetchImpl = async () => { throw new Error(`down ${API_KEY}`); };
  assert.equal(await main(['--live'], env, c.io), 1);
  assert.ok(!c.e.join('\n').includes(API_KEY));
  c = capture();
  assert.equal(await main(['--live'], { N8N_API_KEY: API_KEY }, c.io), 1);
  assert.match(c.e.join(''), /N8N_BASE_URL/);
  c = capture();
  assert.equal(await main([], env, c.io), 2);
  c = capture();
  assert.equal(await main(['--from-dir', 'x', '--live'], env, c.io), 2);
  c = capture();
  assert.equal(await main(['--bogus'], env, c.io), 2);
  c = capture();
  assert.equal(await main(['--help'], env, c.io), 0);
});

test('CLI --from-dir: reads exports, skips junk, exit 1 when nothing found', async () => {
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'src-'));
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'out-'));
  fs.writeFileSync(path.join(src, 'a.json'), JSON.stringify(allExamples()[0]));
  fs.writeFileSync(path.join(src, 'list.json'), JSON.stringify(allExamples().slice(1)));
  fs.writeFileSync(path.join(src, 'api.json'), JSON.stringify({ data: [{ ...allExamples()[0], name: 'From API shape' }] }));
  fs.writeFileSync(path.join(src, 'bad.json'), '{not json');
  fs.writeFileSync(path.join(src, 'other.json'), '{"hello":1}');
  const c = capture();
  assert.equal(await main(['--from-dir', src, '--out', out, '--date', '2026-01-01'], {}, c.io), 0);
  assert.match(c.o[0], /Wrote 9 files for 6 workflow/);
  assert.equal(c.e.filter((l) => /skipped/.test(l)).length, 2);
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'empty-'));
  assert.equal(await main(['--from-dir', empty, '--out', out], {}, capture().io), 1);
  for (const d of [src, out, empty]) fs.rmSync(d, { recursive: true, force: true });
});

test('LLM: prompt contains only names, types, connections', () => {
  const m = analyzeWorkflow(hostile());
  const p = buildPrompt(m);
  for (const v of Object.values(SECRETS)) assert.ok(!p.includes(v));
  assert.ok(!p.includes(CRED_ID));
  assert.ok(!p.includes('internal-client.test'));
  assert.ok(!p.includes('Jane Doe'));
  assert.ok(!p.includes('headerParameters'));
  assert.ok(!p.includes('jsCode'));
  assert.match(p, /"type":"httpRequest"/);
});

test('LLM: ollama, groq, gemini via mock; redirect manual; keys in headers only; failure is soft', async () => {
  const m = analyzeWorkflow(allExamples()[0]);
  const seen = [];
  const mk = (body) => async (url, init) => { seen.push({ url, init }); return json(body); };
  let r = await summarize(m, { HANDOVER_OLLAMA_MODEL: 'llama3.2' }, mk({ response: 'It sends alerts.' }));
  assert.equal(r.text, 'It sends alerts.');
  assert.match(seen[0].url, /127\.0\.0\.1:11434\/api\/generate$/);
  r = await summarize(m, { GROQ_API_KEY: 'gsk_' + 'a'.repeat(30) }, mk({ choices: [{ message: { content: 'Groq says hi' } }] }));
  assert.match(r.provider, /^Groq/);
  assert.ok(!seen[1].url.includes('gsk_'));
  assert.equal(seen[1].init.redirect, 'manual');
  r = await summarize(m, { GEMINI_API_KEY: 'AIza' + 'b'.repeat(35) }, mk({ candidates: [{ content: { parts: [{ text: 'Gemini says hi' }] } }] }));
  assert.match(r.provider, /^Gemini/);
  assert.ok(!seen[2].url.includes('AIza'));
  assert.equal(seen[2].init.headers['x-goog-api-key'].startsWith('AIza'), true);
  const warns = [];
  assert.equal(await summarize(m, { HANDOVER_OLLAMA_MODEL: 'x' }, async () => { throw new Error('connect ECONNREFUSED http://127.0.0.1:11434/x'); }, (w) => warns.push(w)), null);
  assert.ok(!warns[0].includes('127.0.0.1'));
  assert.equal(await summarize(m, {}, mk({})), null);
  const leaky = await summarize(m, { HANDOVER_OLLAMA_MODEL: 'x' }, mk({ response: `Use ${SECRETS.openai} please` }));
  assert.ok(!leaky.text.includes(SECRETS.openai));
});

test('CLI --llm adds the summary, clearly labelled unverified', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-'));
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'llmsrc-'));
  fs.writeFileSync(path.join(src, 'a.json'), JSON.stringify(allExamples()[0]));
  const c = capture();
  c.io.fetchImpl = async () => json({ response: 'Every morning it checks the CRM.' });
  assert.equal(await main(['--from-dir', src, '--out', dir, '--llm', '--date', '2026-01-01'], { HANDOVER_OLLAMA_MODEL: 'm' }, c.io), 0);
  const md = fs.readFileSync(path.join(dir, 'lead-alerts-daily.md'), 'utf8');
  assert.match(md, /AI-written summary \(Ollama m; unverified/);
  assert.match(md, /Every morning it checks the CRM\./);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(src, { recursive: true, force: true });
});
