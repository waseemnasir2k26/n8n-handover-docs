"use strict";
// The strong/weak credential-label rule (src/value-rule.js), checked on both the name policy and the final gate.
const test = require("node:test");
const assert = require("node:assert/strict");
const { sanitizeText } = require("../src/policy");
const { scanText } = require("../src/gate");
const { isLabelledValue, valueShaped } = require("../src/value-rule");

test("strong labels: label + separator + any token is the value, in the policy and the gate", () => {
  for (const t of ["password: tangerine", "pin: 4821", "secret = bluesky", "Passwort is tangerine", "passcode: tangerine"]) {
    assert.notEqual(sanitizeText(t), t, `policy kept: ${t}`);
    assert.ok(scanText(t).length > 0, `gate missed: ${t}`);
  }
});

test("weak labels: plain-letter names are unchanged and exit clean, in the policy and the gate", () => {
  for (const t of ["Credentials: Slack", "Token: refresh job", "API Key: Rotation", "Auth: Callback", "Login: Alerts"]) {
    assert.equal(sanitizeText(t), t, t);
    assert.deepEqual(scanText(t), [], t);
  }
});

test("weak labels: a value-looking token is redacted in the policy and flagged by the gate", () => {
  for (const t of ["Token: ghp_abc123XYZ", "API Key: sk-live-abc123"]) {
    assert.match(sanitizeText(t), /\[redacted\]/, t);
    assert.ok(scanText(t).length > 0, t);
  }
});

test("the shared rule: strong takes any token, weak takes only value-shaped ones", () => {
  assert.equal(isLabelledValue("strong", "tangerine"), true);
  assert.equal(isLabelledValue("weak", "refresh"), false);
  assert.equal(isLabelledValue("weak", "[redacted]"), false);
  assert.equal(valueShaped("ghp_abcdef"), true);
  assert.equal(valueShaped("Callback"), false);
  assert.equal(valueShaped("refresh-job"), false);
});
