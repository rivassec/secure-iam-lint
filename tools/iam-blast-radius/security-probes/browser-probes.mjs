import { chromium } from '@playwright/test';

const TARGET = process.argv[2] || 'https://rivassec.com/tools/iam-blast-radius/';
let pass = 0, fail = 0; const F = [];
const ok = (c, m) => { if (c) pass++; else { fail++; F.push(m); } };

const browser = await chromium.launch();
const page = await browser.newPage();

// Global XSS execution detectors
let dialogFired = false;
page.on('dialog', async (d) => { dialogFired = true; await d.dismiss(); });
const pageErrors = [];
page.on('pageerror', (e) => pageErrors.push(String(e)));
const cspViolations = [];
page.on('console', (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) cspViolations.push(m.text()); });

// Network egress detector: any request to a host other than the tool's origin
const origin = new URL(TARGET).origin;
const egress = [];
page.on('request', (req) => {
  const u = req.url();
  if (u.startsWith('data:') || u.startsWith('blob:')) return;
  if (!u.startsWith(origin)) egress.push(`${req.method()} ${u}`);
});

await page.goto(TARGET, { waitUntil: 'networkidle' });

// Build hostile policies that ALSO trigger findings (Action "*") so payload fields render.
function poly(fields) {
  const stmt = { Sid: 'S', Effect: 'Allow', Action: '*', Resource: '*', ...fields };
  return JSON.stringify({ Version: '2012-10-17', Statement: [stmt] }, null, 2);
}
const payloads = [
  poly({ Sid: '<script>window.__xss=1;alert(1)</script>' }),
  poly({ Sid: '<img src=x onerror="window.__xss=1;alert(2)">' }),
  poly({ Resource: 'arn:aws:s3:::"><svg onload="window.__xss=1;alert(3)">/*' }),
  poly({ Resource: 'javascript:alert(4)' }),
  poly({ Condition: { StringEquals: { 'aws:username': '<iframe src=javascript:alert(5)></iframe>' } } }),
  poly({ Principal: { AWS: '<script>window.__xss=1</script>' } }),
  poly({ Sid: '"><input autofocus onfocus=alert(7)>' }),
  poly({ Resource: ["arn:aws:s3:::a‮/*", 'arn:aws:s3:::b/*'] }),
];

for (let i = 0; i < payloads.length; i++) {
  await page.fill('#policy-input', payloads[i]);
  await page.click('#analyze-btn');
  await page.waitForFunction(() => /complete|could not/i.test(document.querySelector('#status')?.textContent || ''), null, { timeout: 8000 }).catch(() => {});
  const xssFlag = await page.evaluate(() => window.__xss);
  ok(!xssFlag, `payload ${i}: window.__xss set (script executed!)`);
  // No live dangerous nodes synthesized from input in the results region
  const inj = await page.evaluate(() => {
    const r = document.querySelector('main');
    return {
      imgOnerror: [...r.querySelectorAll('img')].filter(e => e.getAttribute('onerror') || e.src.includes('x')).length,
      scripts: [...r.querySelectorAll('script')].length,
      iframes: [...r.querySelectorAll('iframe')].length,
      jsHref: [...r.querySelectorAll('[href^="javascript:"],[src^="javascript:"]')].length,
      svgOnload: [...r.querySelectorAll('svg[onload], *[onload]')].length,
    };
  });
  ok(inj.imgOnerror === 0, `payload ${i}: injected <img> present (${inj.imgOnerror})`);
  ok(inj.scripts === 0, `payload ${i}: <script> injected into results (${inj.scripts})`);
  ok(inj.iframes === 0, `payload ${i}: <iframe> injected (${inj.iframes})`);
  ok(inj.jsHref === 0, `payload ${i}: javascript: href/src present (${inj.jsHref})`);
  ok(inj.svgOnload === 0, `payload ${i}: on* handler attribute present (${inj.svgOnload})`);
}
ok(!dialogFired, 'a dialog (alert/confirm/prompt) fired during XSS battery');

// DoS: huge policy must not hang the tab
const many = JSON.stringify({ Version: '2012-10-17', Statement: Array.from({ length: 20000 }, (_, i) => ({ Sid: 'S' + i, Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b' + i })) });
await page.fill('#policy-input', many);
const t = Date.now();
await page.click('#analyze-btn');
const finished = await page.waitForFunction(() => /complete|could not|too|limit|large|failed/i.test(document.querySelector('#status')?.textContent || ''), null, { timeout: 25000 }).then(() => true).catch(() => false);
ok(finished, `DoS: 20k-statement analysis did not resolve within 25s (status hang)`);
ok(await page.evaluate(() => document.readyState === 'complete'), 'DoS: page not responsive after huge input');
const dosMs = Date.now() - t;

// Export safety: exports must not execute and must be blob downloads
let dl = null;
try {
  await page.fill('#policy-input', poly({ Sid: '<script>alert(99)</script>' }));
  await page.click('#analyze-btn');
  await page.waitForFunction(() => /complete/i.test(document.querySelector('#status')?.textContent || ''), null, { timeout: 8000 }).catch(() => {});
  const [download] = await Promise.all([
    page.waitForEvent('download', { timeout: 8000 }).catch(() => null),
    page.click('#export-json').catch(() => {}),
  ]);
  dl = download;
  ok(!dialogFired, 'export triggered a dialog (execution)');
} catch (e) { ok(false, 'export probe error: ' + e.message); }
ok(dl !== null, 'JSON export did not produce a download');

// Egress verdict (page assets are same-origin; ANY external request is a finding)
ok(egress.length === 0, `network egress to external host(s): ${egress.slice(0, 5).join(' ; ')}`);
ok(pageErrors.length === 0, `page errors: ${pageErrors.slice(0, 3).join(' ; ')}`);

console.log(`BROWSER PROBES @ ${TARGET}`);
console.log(`  ${pass} passed, ${fail} failed`);
console.log(`  dialogFired=${dialogFired}  egress=${egress.length}  cspViolations(console)=${cspViolations.length}  dosMs=${dosMs}`);
if (F.length) console.log('FAILURES:\n - ' + F.join('\n - '));
await browser.close();
