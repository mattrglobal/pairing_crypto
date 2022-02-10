"use strict";

/* eslint-disable @typescript-eslint/no-var-requires */
const fs = require("fs");
const buffer = fs.readFileSync("./lib/web/index_bg.wasm");

fs.writeFileSync(
  "./lib/web/index_wasm_bs64.js",
  `
module.exports = Buffer.from('${buffer.toString("base64")}', 'base64');
`
);