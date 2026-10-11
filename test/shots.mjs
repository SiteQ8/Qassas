// Screenshot routes in both languages and sizes for visual review.
// Usage: node test/shots.mjs http://127.0.0.1:8899 out_dir route1 route2 ...
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const [base, out, ...routes] = process.argv.slice(2);
const browser = await chromium.launch({ args: ['--no-sandbox'] });
const errors = [];
for (const lang of ['ar', 'en']) {
  for (const [w, h, tag] of [[1440, 900, 'd'], [390, 844, 'm']]) {
    const page = await browser.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: 1 });
    page.on('console', (m) => { if (m.type() === 'error') errors.push(`${lang} ${tag} ${m.text()}`); });
    page.on('pageerror', (e) => errors.push(`${lang} ${tag} ${e.message}`));
    for (const r of routes) {
      await page.goto(`${base}/?lang=${lang}#/${r}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(500);
      const name = `${out}/${(r || 'home').replace(/\//g, '_')}-${lang}-${tag}.png`;
      await page.screenshot({ path: name, fullPage: process.env.FULL === '1' });
    }
    await page.close();
  }
}
await browser.close();
console.log(errors.length ? errors.join('\n') : 'no console errors');
