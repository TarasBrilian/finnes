import { chromium } from 'playwright';

const base = process.env.BASE ?? 'http://localhost:3100';
const pages = [
  { path: '/', name: 'home' },
  { path: '/institution', name: 'institution' },
  { path: '/regulator', name: 'regulator' },
];

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();

for (const p of pages) {
  await page.goto(base + p.path, { waitUntil: 'networkidle' });
  await page.waitForTimeout(600);
  await page.screenshot({ path: `/tmp/finnes-${p.name}.png`, fullPage: true });
  console.log(`shot: /tmp/finnes-${p.name}.png`);
}

await browser.close();
