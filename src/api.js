"use strict";
// Read-only client for the n8n public API. GET only. The API key is sent in one
// header, never logged, never put in a URL, and redirects are NOT followed so the
// key can never be forwarded to another host.

function scrubKey(text, key) {
  let s = String(text == null ? "" : text);
  if (key && key.length >= 4) s = s.split(key).join("[API_KEY]");
  return s;
}

function normaliseBase(raw) {
  let u;
  try {
    u = new URL(String(raw || "").trim());
  } catch {
    throw new Error(
      "N8N_BASE_URL is not a valid URL (example: https://n8n.example.com)",
    );
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local))
    throw new Error(
      "N8N_BASE_URL must use https:// (http:// is allowed only for localhost)",
    );
  if (u.username || u.password)
    throw new Error("N8N_BASE_URL must not contain a username or password");
  let p = u.pathname.replace(/\/+$/, "").replace(/\/api\/v1$/, "");
  return `${u.protocol}//${u.host}${p}`;
}

async function fetchWorkflows({
  baseUrl,
  apiKey,
  tag,
  activeOnly,
  limit,
  fetchImpl = globalThis.fetch,
  timeoutMs = 30000,
}) {
  if (!apiKey) throw new Error("N8N_API_KEY is not set");
  const base = normaliseBase(baseUrl);
  const out = [];
  let cursor = null;
  for (let page = 0; page < 100; page++) {
    const qs = new URLSearchParams({ limit: "100" });
    if (tag) qs.set("tags", tag);
    if (activeOnly) qs.set("active", "true");
    if (cursor) qs.set("cursor", cursor);
    const path = "/api/v1/workflows";
    let res;
    try {
      res = await fetchImpl(`${base}${path}?${qs}`, {
        method: "GET",
        redirect: "manual",
        headers: { "X-N8N-API-KEY": apiKey, accept: "application/json" },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      throw new Error(
        scrubKey(
          `Could not reach the n8n API: ${e && e.cause && e.cause.code ? e.cause.code : e && e.name === "TimeoutError" ? "timeout" : "network error"}`,
          apiKey,
        ),
      );
    }
    if (res.status >= 300 && res.status < 400) {
      throw new Error(
        `The n8n API answered with a redirect (HTTP ${res.status}). Not following it, so the API key is never forwarded. Set N8N_BASE_URL to the final URL.`,
      );
    }
    if (res.status === 401 || res.status === 403)
      throw new Error(
        `The n8n API refused the key (HTTP ${res.status}). Check N8N_API_KEY and that the public API is enabled.`,
      );
    if (!res.ok)
      throw new Error(
        `The n8n API request failed: HTTP ${res.status} for GET ${path}`,
      );
    let body;
    try {
      body = await res.json();
    } catch {
      throw new Error(
        "The n8n API returned something that is not JSON. Is N8N_BASE_URL the n8n server?",
      );
    }
    if (!body || !Array.isArray(body.data))
      throw new Error('Unexpected n8n API response shape (no "data" array).');
    out.push(...body.data);
    if (limit && out.length >= limit) return out.slice(0, limit);
    cursor = body.nextCursor;
    if (!cursor) break;
  }
  return out;
}

module.exports = { fetchWorkflows, normaliseBase, scrubKey };
