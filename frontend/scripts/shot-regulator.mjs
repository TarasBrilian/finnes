import { chromium } from 'playwright';
const b = await chromium.launch();
const ctx = await b.newContext({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();
await page.goto('http://localhost:3100/regulator', { waitUntil: 'networkidle' });
await page.waitForTimeout(400);
await page.screenshot({ path: '/tmp/finnes-regulator.png', fullPage: true });
console.log('shot: empty');
// climax: load demo key, select first tx, decrypt
await page.getByRole('button', { name: /Demo key/i }).click();
await page.waitForTimeout(300);
await page.locator('ul li button').first().click();
await page.waitForTimeout(300);
await page.getByRole('button', { name: /Decrypt with view key/i }).click();
await page.waitForTimeout(700);
await page.screenshot({ path: '/tmp/finnes-regulator-revealed.png', fullPage: true });
console.log('shot: revealed');
await b.close();
