/**
 * gen-ui.cjs
 * Extracts buildEmbeddedAdminHTML from the worker and writes public/index.html.
 * Run: node scripts/gen-ui.cjs
 */
'use strict';
const fs = require('fs');
const path = require('path');

const SHOP   = 'gerberchildrenswear.myshopify.com';
const ORIGIN = 'https://commerce-shield-prod.ncassidy.workers.dev';

const workerCode = fs.readFileSync(
  path.join(__dirname, '../worker/src/index.js'),
  'utf8'
);

// Locate the template literal inside buildEmbeddedAdminHTML
const fnMarker  = '\nfunction buildEmbeddedAdminHTML(shop, origin) {';
const fnStart   = workerCode.indexOf(fnMarker);
if (fnStart === -1) throw new Error('buildEmbeddedAdminHTML not found in worker/src/index.js');

const returnStart = workerCode.indexOf('return `', fnStart) + 'return `'.length;
// File may use CRLF or LF endings; try both
const fnEnd = (() => {
  for (const pat of ['`;\r\n}', '`;\n}']) {
    const idx = workerCode.lastIndexOf(pat, returnStart + 200000);
    if (idx > returnStart) return idx;
  }
  return -1;
})();
if (fnEnd === -1) throw new Error('Could not locate closing backtick of buildEmbeddedAdminHTML');

const template = workerCode.slice(returnStart, fnEnd);

const html = template
  .replace(/\$\{shop\}/g,   SHOP)
  .replace(/\$\{origin\}/g, ORIGIN)
  // Unescape template-literal escapes that appear verbatim in the source
  .replace(/\\\//g,  '/')
  .replace(/\\'/g,   "'")
  .replace(/<\\\/script>/g, '</script>');

const outPath = path.join(__dirname, '../public/index.html');
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, html, 'utf8');
console.log(`UI written to public/index.html (${html.length} bytes), shop=${SHOP}`);
