// Builds the static website into dist/ for Vercel or any static host.
// app/index.html is a page fragment (the same file is used for the Claude preview),
// so this wraps it in a full HTML document and copies the SDK and images next to it.
// No dependencies: run with `node scripts/build-web.mjs`.
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'dist');

const page = readFileSync(join(root, 'app/index.html'), 'utf8')
  .replace(/<meta name="claude:viewport-fit-sides"[^>]*>\n?/, '');
const bodyStart = page.indexOf('<canvas id="board"');
if (bodyStart < 0) throw new Error('app/index.html: could not find where the page body starts (<canvas id="board">).');
if (!page.includes("from './sdk/index.js'")) throw new Error("app/index.html must import the SDK from './sdk/index.js'.");

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="description" content="Quantum-resistant SOL vaults secured by Winternitz hash signatures.">
<meta property="og:title" content="Quantities">
<meta property="og:description" content="Quantum-resistant SOL vaults secured by Winternitz hash signatures.">
<link rel="icon" type="image/png" href="assets/quant-icon.png">
<link rel="apple-touch-icon" href="assets/quant-icon.png">
<style>:root{padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}body{margin:0}img{max-width:100%}[hidden]{display:none!important}</style>
${page.slice(0, bodyStart).trim()}
</head>
<body>
${page.slice(bodyStart).trim()}
</body>
</html>
`;

rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, 'sdk'), { recursive: true });
writeFileSync(join(out, 'index.html'), html);
cpSync(join(root, 'sdk/index.js'), join(out, 'sdk/index.js'));
cpSync(join(root, 'app/assets'), join(out, 'assets'), { recursive: true });
console.log('Built dist/ (index.html, sdk/index.js, assets/)');
