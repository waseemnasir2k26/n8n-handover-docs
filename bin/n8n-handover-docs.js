#!/usr/bin/env node
"use strict";
const { main } = require("../src/cli");

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    process.stderr.write(
      `error: ${e && e.message ? e.message.replace(/\s+/g, " ").slice(0, 200) : "unexpected failure"}\n`,
    );
    process.exitCode = 1;
  },
);
