// Browser tests for the site. Serves docs/ itself, then drives every route and lab.
// Run: node test/ui.mjs   (set PLAYWRIGHT_MODULE if playwright is not resolvable)
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../docs/', import.meta.url));
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml',
  '.jpg': 'image/jpeg', '.png': 'image/png', '.woff2': 'font/woff2', '.mp4': 'video/mp4', '.vtt': 'text/vtt', '.zip': 'application/zip',
  '.pdf': 'application/pdf', '.jsonl': 'application/json', '.lnk': 'application/octet-stream', '.pcap': 'application/octet-stream' };
const server = createServer(async (req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname)).replace(/^\/+/, '') || 'index.html';
  if (path.startsWith('..')) { res.writeHead(403); res.end(); return; }
  try {
    const body = await readFile(join(root, path));
    res.writeHead(200, { 'content-type': types[extname(path)] || 'application/octet-stream' });
    res.end(body);
  } catch { res.writeHead(404); res.end('not found'); }
}).listen(0);
const base = `http://127.0.0.1:${server.address().port}`;
const bundle = JSON.parse(await readFile(join(root, 'data/bundle.json'), 'utf8'));

let failures = 0;
let passes = 0;
const ok = (cond, msg) => { if (cond) passes++; else { failures++; console.error('FAIL ' + msg); } };

const routes = ['', 'learn', ...bundle.modules.map((m) => 'learn/' + m.id), 'labs', ...bundle.labs.map((l) => 'labs/' + l.id),
  'case', 'watch', 'law', 'law/SA', 'law/INTL', 'tools', 'glossary', 'about', 'nowhere'];
const enPhrases = Object.values(bundle.ui).map((v) => v.en).filter((s) => s.split(' ').length >= 3 && !/[{]/.test(s));

const browser = await chromium.launch({ args: ['--no-sandbox'] });
for (const lang of ['ar', 'en']) {
  for (const width of [390, 1280]) {
    const page = await browser.newPage({ viewport: { width, height: 900 } });
    const errors = [];
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    page.on('pageerror', (e) => errors.push(e.message));
    await page.goto(`${base}/?lang=${lang}`, { waitUntil: 'networkidle' });
    for (const r of routes) {
      await page.evaluate((h) => { location.hash = '#/' + h; }, r);
      await page.waitForTimeout(r.startsWith('labs/') || r === 'case' ? 400 : 120);
      const tag = `${lang} ${width} /${r}`;
      const info = await page.evaluate(async () => {
        window.scrollTo(0, document.body.scrollHeight);
        await new Promise((res) => setTimeout(res, 150));
        const imgs = [...document.querySelectorAll('main img')];
        await Promise.all(imgs.map((i) => (i.complete ? null : new Promise((res) => { i.onload = i.onerror = res; }))));
        const text = document.querySelector('main').innerText;
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        const arabicInEn = [];
        while (walker.nextNode()) {
          const n = walker.currentNode;
          const el = n.parentElement;
          if (!/[\u0600-\u06FF]/.test(n.textContent)) continue;
          if (el.closest('[lang="ar"], .evidence, script, noscript, option')) continue;
          if (el.offsetParent === null && el.tagName !== 'BODY') continue;
          arabicInEn.push(n.textContent.trim().slice(0, 40));
        }
        return {
          lang: document.documentElement.lang,
          dir: document.documentElement.dir,
          h1: !!document.querySelector('main h1'),
          overflow: document.documentElement.scrollWidth - window.innerWidth,
          broken: imgs.filter((i) => !i.naturalWidth).map((i) => i.getAttribute('src')),
          bad: (text.match(/\b(undefined|null|NaN|\[object Object\])\b/g) || []),
          text,
          arabicInEn,
        };
      });
      ok(info.lang === lang && info.dir === (lang === 'ar' ? 'rtl' : 'ltr'), `${tag} lang/dir`);
      ok(info.h1, `${tag} has an h1`);
      ok(info.overflow <= 1, `${tag} horizontal overflow ${info.overflow}px`);
      ok(info.broken.length === 0, `${tag} broken images ${info.broken.join(', ')}`);
      ok(info.bad.length === 0, `${tag} leaked ${info.bad.join(', ')}`);
      if (lang === 'ar') {
        const leaked = enPhrases.filter((p) => info.text.includes(p));
        ok(leaked.length === 0, `${tag} English UI text in Arabic page: ${leaked.slice(0, 3).join(' | ')}`);
      } else {
        ok(info.arabicInEn.length === 0, `${tag} Arabic text in English page: ${info.arabicInEn.slice(0, 3).join(' | ')}`);
      }
    }
    ok(errors.length === 0, `${lang} ${width} console errors: ${errors.slice(0, 3).join(' | ')}`);
    await page.close();
  }
}

// ---------------------------------------------------------------- labs work end to end
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
const errs = [];
page.on('pageerror', (e) => errs.push(e.message));
await page.goto(`${base}/?lang=en#/labs/hash`, { waitUntil: 'networkidle' });
await page.waitForSelector('#hash-out dl');
const sample = bundle.ui['hash.sample'].en;
const want = createHash('sha256').update(sample).digest('hex');
const wantMd5 = createHash('md5').update(sample).digest('hex');
const shown = await page.textContent('#hash-out');
ok(shown.includes(want) && shown.includes(wantMd5), 'hash lab shows the same SHA-256 and MD5 as Node');
await page.click('#flip');
await page.waitForSelector('.avalanche');
const bits = Number((await page.textContent('.avalanche')).match(/\d+/)[0]);
ok(bits > 80 && bits < 176, `flipping one bit changes about half of SHA-256 (${bits})`);

await page.goto(`${base}/?lang=en#/labs/signature`, { waitUntil: 'networkidle' });
await page.click('[data-sample$="invoice_0921.jpg"]');
await page.waitForSelector('.verdict');
ok(await page.$('.verdict.mismatch'), 'signature lab flags the renamed archive');
await page.click('[data-sample$="IMG_2038.jpg"]');
await page.waitForSelector('.verdict.match');
ok(true, 'signature lab accepts a real JPEG');

await page.goto(`${base}/?lang=ar#/labs/exif`, { waitUntil: 'networkidle' });
await page.click('[data-sample$="deleted_photo.jpg"]');
await page.waitForSelector('.near .best');
ok((await page.textContent('.near .best')).includes('السالمية'), 'EXIF lab places the deleted photo in Salmiya');
ok((await page.textContent('#exif-out')).includes('2026-10-03T16:12:40Z'), 'EXIF lab converts Kuwait time to UTC');

await page.goto(`${base}/?lang=en#/labs/custody`, { waitUntil: 'networkidle' });
await page.waitForSelector('#cus-list li');
await page.click('#verify');
await page.waitForSelector('.verdict.match');
ok(true, 'custody lab verifies the intact log in the browser');
await page.fill('input[data-i="2"][data-k="note"]', 'changed');
await page.dispatchEvent('input[data-i="2"][data-k="note"]', 'change');
await page.click('#verify');
await page.waitForSelector('.verdict.mismatch');
ok((await page.$$eval('#cus-list li.broken .seq', (n) => n.map((x) => x.textContent))).join() === '3', 'editing entry 3 breaks exactly entry 3');
await page.click('#load-archive');
await page.waitForTimeout(200);
await page.click('#verify');
await page.waitForSelector('.verdict.mismatch');
ok((await page.$$eval('#cus-list li.broken .seq', (n) => n.map((x) => x.textContent))).join() === '5', 'archived copy breaks at entry 5');

await page.goto(`${base}/?lang=en#/labs/timeline`, { waitUntil: 'networkidle' });
await page.waitForSelector('#tl-list li');
ok((await page.$$('#tl-list li.pivot')).length === 9, 'timeline shows the nine key moments');
const before = await page.textContent('#tl-list li time');
await page.click('[data-zone="utc"]');
const after = await page.textContent('#tl-list li time');
ok(before.includes('08:42:09 +03') && after.includes('05:42:09 UTC'), `zone switch converts times (${before} / ${after})`);

await page.goto(`${base}/?lang=en#/case`, { waitUntil: 'networkidle' });
const imageSha = await page.evaluate(async () => {
  const res = await fetch('labs/case-01/custody/custody.jsonl');
  const lines = (await res.text()).trim().split('\n').map((l) => JSON.parse(l));
  return lines.find((e) => e.action === 'imaged').item_sha256;
});
const answers = { q01: imageSha, q02: 'invoice_0921.jpg', q03: 'Salmiya', q04: 'dar-alsanbouk-login.example', q05: '09:27', q06: '60',
  q07: '5', q08: '2', q09: 'C:\\Users\\fahad\\Downloads\\Tender_Update\\update.exe', q10: '2', q11: 'SanboukUpdater', q12: '43' };
for (const [q, v] of Object.entries(answers)) await page.fill(`#a-${q}`, v);
await page.click('#answers button[type="submit"]');
await page.waitForFunction(() => /12/.test(document.querySelector('#score').textContent));
ok((await page.textContent('#score')).includes('12 of 12'), 'the case scores 12 of 12 with the right answers');
await page.fill('#a-q03', 'Jahra');
await page.click('#answers button[type="submit"]');
await page.waitForFunction(() => document.querySelector('#score').textContent.includes('11'));
ok(true, 'a wrong answer is marked wrong');

await page.goto(`${base}/?lang=en#/learn/acquisition`, { waitUntil: 'networkidle' });
const q = bundle.modules.find((m) => m.id === 'acquisition').quiz[0];
await page.check(`input[name="acquisition-0"][value="${q.answer}"]`);
ok(await page.$('fieldset.q.right'), 'quiz marks the right answer');
await page.click('#lang');
await page.waitForTimeout(150);
ok((await page.getAttribute('html', 'dir')) === 'rtl', 'language toggle switches to Arabic');
ok(errs.length === 0, 'no page errors in lab runs: ' + errs.join(' | '));

await browser.close();
server.close();
console.log(`ui: ${passes} passed, ${failures} failed`);
process.exit(failures ? 1 : 0);
