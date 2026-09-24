import {defineConfig} from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 120_000,
  workers: 1,
  use: {
    baseURL: 'http://127.0.0.1:9100',
    viewport: {width: 1920, height: 1080},
    deviceScaleFactor: 1,
    browserName: 'chromium',
  },
  webServer: {
    command: 'npm start -- --port 9100 --strictPort',
    url: 'http://127.0.0.1:9100/tests/harness.html',
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
