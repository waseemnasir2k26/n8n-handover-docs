"use strict";
// Optional plain-English summary from a FREE LLM. Opt-in (--llm). The model only
// ever receives node names, node types and connections: no parameters, no
// credentials, no pinned data, no URLs.
const { structureForLLM } = require("./parse");
const { scrubText } = require("./secrets");
const { clean } = require("./util");

function buildPrompt(model) {
  const s = structureForLLM(model);
  return [
    "You are documenting an n8n automation for a client handover.",
    "Using ONLY the structure below (node names, node types, connections), write 3 to 5 plain-English sentences for a non-technical owner:",
    "what it appears to do, what starts it, and what it talks to. Do not invent details that are not in the structure. No markdown, no lists.",
    "",
    JSON.stringify(s),
  ].join("\n");
}

function pickProvider(env) {
  if (env.HANDOVER_OLLAMA_MODEL) return "ollama";
  if (env.GROQ_API_KEY) return "groq";
  if (env.GEMINI_API_KEY) return "gemini";
  return null;
}

async function post(url, headers, body, fetchImpl, key) {
  const res = await fetchImpl(url, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60000),
  });
  if (res.status >= 300 && res.status < 400)
    throw new Error("LLM endpoint redirected; refusing to follow");
  if (!res.ok) throw new Error(`LLM request failed: HTTP ${res.status}`);
  return res.json();
}

function finish(text) {
  const t = scrubText(clean(text)).replace(/\s+/g, " ").trim().slice(0, 1200);
  return t || null;
}

/** @returns {Promise<{provider:string,text:string}|null>} null when no provider is configured or the call fails */
async function summarize(
  model,
  env = process.env,
  fetchImpl = globalThis.fetch,
  warn = () => {},
) {
  const provider = pickProvider(env);
  if (!provider) return null;
  const prompt = buildPrompt(model);
  try {
    if (provider === "ollama") {
      const host = (env.OLLAMA_HOST || "http://127.0.0.1:11434").replace(
        /\/+$/,
        "",
      );
      const j = await post(
        `${host}/api/generate`,
        {},
        {
          model: env.HANDOVER_OLLAMA_MODEL,
          prompt,
          stream: false,
          options: { temperature: 0.2 },
        },
        fetchImpl,
      );
      const text = finish(j && j.response);
      return text
        ? {
            provider: `Ollama ${clean(env.HANDOVER_OLLAMA_MODEL).slice(0, 60)}`,
            text,
          }
        : null;
    }
    if (provider === "groq") {
      const mdl = env.HANDOVER_GROQ_MODEL || "llama-3.1-8b-instant";
      const j = await post(
        "https://api.groq.com/openai/v1/chat/completions",
        { authorization: `Bearer ${env.GROQ_API_KEY}` },
        {
          model: mdl,
          temperature: 0.2,
          max_tokens: 300,
          messages: [{ role: "user", content: prompt }],
        },
        fetchImpl,
      );
      const text = finish(
        j &&
          j.choices &&
          j.choices[0] &&
          j.choices[0].message &&
          j.choices[0].message.content,
      );
      return text
        ? { provider: `Groq ${clean(mdl).slice(0, 60)}`, text }
        : null;
    }
    const mdl = env.HANDOVER_GEMINI_MODEL || "gemini-2.5-flash";
    const j = await post(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(mdl)}:generateContent`,
      { "x-goog-api-key": env.GEMINI_API_KEY },
      {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 300 },
      },
      fetchImpl,
    );
    const parts =
      j &&
      j.candidates &&
      j.candidates[0] &&
      j.candidates[0].content &&
      j.candidates[0].content.parts;
    const text = finish(parts && parts.map((p) => p.text || "").join(" "));
    return text
      ? { provider: `Gemini ${clean(mdl).slice(0, 60)}`, text }
      : null;
  } catch (e) {
    // never include e.message verbatim: it could echo a URL; keep it generic
    warn(
      `LLM summary skipped (${provider}): ${
        e && e.name === "TimeoutError"
          ? "timeout"
          : String(e && e.message)
              .replace(/https?:\/\/\S+/g, "[url]")
              .slice(0, 80)
      }`,
    );
    return null;
  }
}

module.exports = { summarize, buildPrompt, pickProvider };
