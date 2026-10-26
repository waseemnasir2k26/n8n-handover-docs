"use strict";
// ONE rule for "the token after a credential label is the credential", shared by the name policy
// (src/policy.js) and the final gate (src/gate.js). The words and their strength live in src/labels.js.
//   strong (password, pass, pwd, pw, passphrase, passcode, pin, secret ...): label + separator
//     (: = - is) + ANY non-empty token -> that token is the value.
//   weak (credential(s), token, api key, auth, login, key, access ...): only a VALUE-SHAPED token is
//     the value (a digit, a symbol, a known key shape, a long high-entropy run). Plain letters
//     ("Token: refresh job", "Login: Alerts") are an ordinary name.
// The dash exemption for plain-word names ("Password - Reset Flow") belongs to the callers.

const KEY_PREFIX =
  /^(?:sk|pk|rk|ghp|gho|ghs|ghu|github_pat|glpat|xox[abposr]|hf|ya29)[-_][A-Za-z0-9]/;
const KEY_GLUED = /^(?:AKIA|ASIA|AIza|eyJ)[A-Za-z0-9_-]{8,}/;
const HEX_RUN = /[0-9a-fA-F]{16,}/;
const SYMBOL = /[@#$%^&*+=~|\\!?]/;
const EDGE_OPEN = /^["'`([{<“‘]+/;
const EDGE_CLOSE = /["'`)\]}>”’,;:.!?…]+$/;

function entropy(s) {
  const f = new Map();
  for (const c of s) f.set(c, (f.get(c) || 0) + 1);
  let h = 0;
  for (const k of f.values()) h -= (k / s.length) * Math.log2(k / s.length);
  return h;
}

/** Does this token look like a value on its own (a digit, a symbol, a known key shape, high entropy)? */
function valueShaped(token) {
  const c = String(token == null ? "" : token)
    .replace(EDGE_OPEN, "")
    .replace(EDGE_CLOSE, "");
  if (!/[\p{L}\p{N}]/u.test(c)) return false;
  if (KEY_PREFIX.test(c) || KEY_GLUED.test(c) || HEX_RUN.test(c)) return true;
  if (/\p{N}/u.test(c) || SYMBOL.test(c)) return true;
  return [...c].length >= 20 && entropy(c) >= 4.2;
}

/**
 * kind: "strong" | "weak". token: the first token after the label and its separator.
 * True when that token is the credential value under the strong/weak rule.
 */
function isLabelledValue(kind, token) {
  const c = String(token == null ? "" : token);
  if (!/[\p{L}\p{N}]/u.test(c) || /^\\?\[?redacted/i.test(c)) return false;
  if (kind === "strong") return true;
  if (kind === "weak") return valueShaped(c);
  return false;
}

module.exports = { isLabelledValue, valueShaped };
