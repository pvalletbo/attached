// npm run render                  → output/attached-explained.mp4
// npm run render -- --seconds 1    → output/attached-smoke-test.mp4
// npm run render -- --style zine   → output/attached-zine.mp4
// Install Chromium first with: npx playwright install chromium
import {chromium} from '@playwright/test';
import {createServer} from 'vite';
import {fileURLToPath} from 'node:url';

import {parseArgs} from 'node:util';

const {values} = parseArgs({options: {
  style: {type: 'string', default: 'original'},
  seconds: {type: 'string'},
  help: {type: 'boolean'},
}});
if (values.help) {
  console.log('Render at 1920×1080 / 30 fps.\nUsage: npm run render -- [--style original|zine] [--seconds <positive number>]\nInstall the browser first: npx playwright install chromium');
  process.exit(0);
}
const style = values.style;
if (!['original', 'zine'].includes(style)) throw new Error('Style must be original or zine.');
const seconds = values.seconds === undefined ? undefined : Number(values.seconds);
if (seconds !== undefined && (!Number.isFinite(seconds) || seconds <= 0)) {
  throw new Error('Seconds must be a positive number.');
}
const filename = style === 'zine'
  ? (seconds ? 'attached-zine-smoke-test' : 'attached-zine')
  : (seconds ? 'attached-smoke-test' : 'attached-explained');

process.chdir(fileURLToPath(new URL('..', import.meta.url)));
const server = await createServer({server: {host: '127.0.0.1', port: 0, open: false}});
let browser;
try {
  await server.listen();
  browser = await chromium.launch();
  const page = await browser.newPage({viewport: {width: 1920, height: 1080}});
  page.on('pageerror', error => console.error(error));
  const {port} = server.httpServer.address();
  await page.goto(`http://127.0.0.1:${port}/tests/harness.html?style=${style}`);
  await page.waitForFunction(() => window.animation?.ready, undefined, {timeout: 60_000});
  console.log('Rendering. This can take several minutes…');
  await page.evaluate(seconds => window.animation.render(seconds), seconds);
  console.log(`Saved output/${filename}.mp4`);
} finally {
  await browser?.close();
  await server.close();
}
