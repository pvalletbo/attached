import {expect, test} from '@playwright/test';
import {spawnSync} from 'node:child_process';
import {stat} from 'node:fs/promises';
import {SHOTS, ZINE_DURATION} from '../src/zine/script';
import {COMMANDS} from '../src/storyboard';
import type {} from './harness';

test('zine script is a shorter edit with readable captions and separate direct/relay cuts', () => {
  expect(ZINE_DURATION).toBe(75);
  expect(new Set(SHOTS.map(shot => shot.id)).size).toBe(SHOTS.length);
  expect(SHOTS.map(shot => shot.id)).toContain('direct');
  expect(SHOTS.map(shot => shot.id)).toContain('relay');
  for (const shot of SHOTS) {
    expect(shot.caption.split(/\s+/).length / shot.seconds).toBeLessThanOrEqual(3.5);
  }
});

test('render CLI accepts style selection and rejects invalid inputs before launching a browser', () => {
  const help = spawnSync(process.execPath, ['scripts/render.mjs', '--help'], {encoding: 'utf8'});
  expect(help.status).toBe(0);
  expect(help.stdout).toContain('--style original|zine');
  for (const args of [['--style', 'unknown'], ['--seconds', '0'], ['--seconds', 'NaN']]) {
    const result = spawnSync(process.execPath, ['scripts/render.mjs', ...args], {encoding: 'utf8'});
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/Style must be|Seconds must be/);
  }
});

test('every zine cut draws its headline and caption inside the frame', async ({page}, testInfo) => {
  const browserErrors: string[] = [];
  page.on('pageerror', error => browserErrors.push(error.message));
  await page.goto('/tests/harness.html?style=zine');
  await page.waitForFunction(() => window.animation?.ready);
  expect(await page.evaluate(() => window.animation.duration)).toBeCloseTo(ZINE_DURATION, 0);
  expect(await page.evaluate(() => document.fonts.check('126px Anton'))).toBe(true);
  let time = 0;
  for (const shot of SHOTS) {
    const snapshot = await page.evaluate(seconds => window.animation.seek(seconds), time + shot.seconds - 0.5);
    const texts = snapshot.texts.map(node => node.text);
    expect(texts).toContain(shot.headline);
    expect(texts).toContain(shot.caption);
    if (shot.id === 'work') {
      expect(texts.join('\n')).toContain(COMMANDS.exportSsh);
      expect(texts.join('\n')).toContain(COMMANDS.addMachine);
    }
    // Deliberately rotated paper and large type are fine; cropped words are not.
    for (const node of snapshot.texts) {
      expect(node.left, node.text).toBeGreaterThanOrEqual(25);
      expect(node.right, node.text).toBeLessThanOrEqual(1895);
      expect(node.top, node.text).toBeGreaterThanOrEqual(25);
      expect(node.bottom, node.text).toBeLessThanOrEqual(1040);
    }
    await page.locator('canvas').screenshot({path: testInfo.outputPath(`${shot.id}.png`)});
    time += shot.seconds;
  }
  const backwards = await page.evaluate(() => window.animation.seek(4.5));
  expect(backwards.texts.map(node => node.text)).toContain(SHOTS[0].headline);
  expect(await page.evaluate(() => window.animation.errors)).toEqual([]);
  expect(browserErrors).toEqual([]);
});

test('zine exports to its own MP4 without replacing the original', async ({page}) => {
  await page.goto('/tests/harness.html?style=zine');
  await page.waitForFunction(() => window.animation?.ready);
  await page.evaluate(() => window.animation.render(1));
  expect((await stat('output/attached-zine-smoke-test.mp4')).size).toBeGreaterThan(10_000);
});
