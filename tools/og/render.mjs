// Render docs/og.png from tools/og/og.html. Run: node tools/og/render.mjs
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const browser = await chromium.launch({ args: ['--no-sandbox', '--allow-file-access-from-files'] });
const page = await browser.newPage({ viewport: { width: 1200, height: 630 } });
await page.goto('file://' + fileURLToPath(new URL('./og.html', import.meta.url)));
await page.evaluate(async () => { await document.fonts.ready; const i = document.querySelector('img'); if (!i.complete) await new Promise((r) => { i.onload = i.onerror = r; }); return i.naturalWidth; });
await page.waitForTimeout(300);
await page.screenshot({ path: fileURLToPath(new URL('../../docs/og.png', import.meta.url)) });
await browser.close();
console.log('wrote docs/og.png');
