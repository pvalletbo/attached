// npm run render                  → output/attached-explained.mp4
// npm run render -- --seconds 1    → output/attached-smoke-test.mp4
// Install Chromium first with: npx playwright install chromium
import {chromium} from '@playwright/test';
import {createServer} from 'vite';
import {fileURLToPath} from 'node:url';

const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('Render the captioned Attached explainer at 1920×1080 / 30 fps.\nUsage: npm run render [-- --seconds <positive number>]\nInstall the browser first: npx playwright install chromium');
  process.exit(0);
}
let seconds;
if (args.length) {
  seconds = Number(args[1]);
  if (args.length !== 2 || args[0] !== '--seconds' || !Number.isFinite(seconds) || seconds <= 0) {
    throw new Error('Usage: npm run render [-- --seconds <positive number>]');
  }
}

process.chdir(fileURLToPath(new URL('..', import.meta.url)));
const server = await createServer({server: {host: '127.0.0.1', port: 0, open: false}});
let browser;
try {
  await server.listen();
  browser = await chromium.launch();
  const page = await browser.newPage({viewport: {width: 1920, height: 1080}});
  page.on('pageerror', error => console.error(error));
  const {port} = server.httpServer.address();
  await page.goto(`http://127.0.0.1:${port}/tests/harness.html`);
  await page.waitForFunction(() => window.animation?.ready, undefined, {timeout: 60_000});
  console.log('Rendering. This can take several minutes…');
  await page.evaluate(seconds => window.animation.render(seconds), seconds);
  console.log(`Saved output/${seconds ? 'attached-smoke-test' : 'attached-explained'}.mp4`);
} finally {
  await browser?.close();
  await server.close();
}
