#!/usr/bin/env node
"use strict";
// npm run readme:langs: rewrite the language list in README.md from src/labels.js so they cannot drift.
const fs = require("node:fs");
const path = require("node:path");
const { LANGUAGES } = require("../src/labels");

const file = path.join(__dirname, "..", "README.md");
const s = fs.readFileSync(file, "utf8");
const out = s.replace(
  /<!-- langs:start -->[\s\S]*?<!-- langs:end -->/,
  `<!-- langs:start -->${LANGUAGES.join(", ")}<!-- langs:end -->`,
);
if (out === s) console.log("README language list is already up to date");
else {
  fs.writeFileSync(file, out);
  console.log("README language list updated");
}
