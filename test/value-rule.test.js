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

test("weak labels: two or more plain words after a colon are a name, in the policy and the gate", () => {
  for (const t of ["Credentials: Google Sheets", "Token: refresh job", "Access Token: refresh job"]) {
    assert.equal(sanitizeText(t), t, t);
    assert.deepEqual(scanText(t), [], t);
  }
});

test("weak labels: ONE plain word that ends the name is the value, in the policy and the gate", () => {
  for (const t of ["Token: Zebra", "Access Token: zebra", "API Key: Rotation", "Auth: Callback", "Login: Alerts", "Token: ghp_abc123XYZ", "API Key: sk-live-abc123"]) {
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

test("accents and look-alike letters fold before label matching, in the policy and the gate", () => {
  for (const t of ["Passwörd: tangerine", "Pásswórd: tangerine", "Sécret: x1y2"]) {
    assert.notEqual(sanitizeText(t), t, `policy kept: ${t}`);
    assert.ok(scanText(t).length > 0, `gate missed: ${t}`);
  }
});

test("label phrases: any strong word among up to three words before the separator makes the phrase strong", () => {
  for (const t of ["Secret Key: tangerine", "Admin Password: tangerine", "Door PIN: 4821", "Wifi pass: tangerine", "Secret Key:tangerine"]) {
    assert.match(sanitizeText(t), /\[redacted\]/, `policy kept: ${t}`);
    assert.ok(scanText(t).length > 0, `gate missed: ${t}`);
  }
  assert.equal(sanitizeText("Secret Key: tangerine"), "Secret Key: [redacted]");
});

test("= is an assignment: a weak or strong label, = and any token is the value; : keeps the weak/strong rule", () => {
  for (const t of ["api key = tangerine", "token=abc"]) {
    assert.match(sanitizeText(t), /\[redacted\]/, t);
    assert.ok(scanText(t).length > 0, t);
  }
  assert.equal(sanitizeText("Credentials: Slack"), "Credentials: [redacted]");
  assert.equal(sanitizeText("Token: refresh job"), "Token: refresh job");
  assert.match(sanitizeText("password: tangerine"), /\[redacted\]/);
});

test("dash rule: strong + dash + ONE token at the end redacts; two or more plain words are a name", () => {
  for (const t of ["Secret - tangerine", "Password - hunter2", "Secret Key - Rotation", "Password - Winter25x"]) {
    assert.match(sanitizeText(t), /\[redacted\]/, t);
    assert.ok(scanText(t).length > 0, t);
  }
  for (const t of ["Password - Reset Flow", "Secret - Vault Backup"]) {
    assert.equal(sanitizeText(t), t, t);
    assert.deepEqual(scanText(t), [], t);
  }
});

test("dash rule: weak + dash + any plain words is a name; a value-looking token is redacted", () => {
  for (const t of ["Credentials - Slack", "Token - Usage Report", "API Key - Rotation", "Login - Alerts"]) {
    assert.equal(sanitizeText(t), t, t);
    assert.deepEqual(scanText(t), [], t);
  }
  assert.match(sanitizeText("Token - ghp_abc123XYZ"), /\[redacted\]/);
});

test("phrase allow-list: Secret Santa, Key Accounts, PIN Code Generator are never labels", () => {
  for (const t of ["Secret Santa: Alice Smith", "Key Accounts: Alice", "Key Results: Q3 Growth", "PIN Code Generator - Sheet", "Secret Sauce - Recipe"]) {
    assert.equal(sanitizeText(t), t, t);
    assert.deepEqual(scanText(t), [], t);
  }
  assert.match(sanitizeText("Secret Santa Password: tangerine"), /\[redacted\]/);
});

test("Pin: Board Meeting is over-redacted by design (a strong label with a colon takes the next word)", () => {
  assert.equal(sanitizeText("Pin: Board Meeting"), "Pin: [redacted] Meeting");
  assert.ok(scanText("Pin: Board Meeting").length > 0);
});
