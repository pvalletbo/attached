import {expect, test} from '@playwright/test';
import {stat} from 'node:fs/promises';
import {CHAPTERS, COMMANDS, DURATION_SECONDS, chapterDuration} from '../src/storyboard';
import type {} from './harness';

test('storyboard gives every caption time to be read and covers the correct workflow', () => {
  expect(CHAPTERS.map(chapter => chapter.id)).toEqual(['overview', 'setup', 'discovery', 'tunnel', 'ssh', 'workflow']);
  expect(DURATION_SECONDS).toBe(113);
  for (const chapter of CHAPTERS) {
    for (const beat of chapter.beats) {
      // At most 3.5 words/second, allowing time to inspect the diagram too.
      expect(beat.caption.split(/\s+/).length / beat.seconds).toBeLessThanOrEqual(3.5);
    }
  }
  expect(COMMANDS.publish).toBe('attached account export --type publish');
  expect(COMMANDS.serve).toBe('attached serve --host-label office');
  expect(COMMANDS.addMachine).toBe('herdr machine add attached-office --label Office');
});

test('every caption renders, stays in frame, and can be sought backwards', async ({page}, testInfo) => {
  const browserErrors: string[] = [];
  page.on('pageerror', error => browserErrors.push(error.message));
  await page.goto('/tests/harness.html');
  await page.waitForFunction(() => window.animation?.ready);
  expect(await page.evaluate(() => window.animation.duration)).toBeCloseTo(DURATION_SECONDS, 0);
  expect(await page.evaluate(() => document.fonts.check('600 64px Inter') && document.fonts.check('22px "JetBrains Mono"'))).toBe(true);

  let time = 0;
  for (const chapter of CHAPTERS) {
    let beatTime = time + 0.6;
    for (const [index, beat] of chapter.beats.entries()) {
      // Sample near the end of each beat, after all of its reveal animations.
      const snapshot = await page.evaluate(seconds => window.animation.seek(seconds), beatTime + beat.seconds - 0.7);
      expect(snapshot.scene).toBe(chapter.id);
      const text = snapshot.texts.map(node => node.text);
      expect(text).toContain(chapter.title);
      expect(text).toContain(beat.caption);
      for (const node of snapshot.texts) {
        // Motion Canvas uses a top-left world origin after the view transform.
        expect(node.left, node.text).toBeGreaterThanOrEqual(60);
        expect(node.right, node.text).toBeLessThanOrEqual(1860);
        expect(node.top, node.text).toBeGreaterThanOrEqual(25);
        expect(node.bottom, node.text).toBeLessThanOrEqual(1040);
      }
      await page.locator('canvas').screenshot({path: testInfo.outputPath(`${chapter.id}-${index + 1}.png`)});
      beatTime += beat.seconds;
    }
    time += chapterDuration(chapter);
  }
  const backwards = await page.evaluate(() => window.animation.seek(9));
  expect(backwards.scene).toBe('overview');
  expect(backwards.texts.map(node => node.text)).toContain('No open SSH port');
  expect(await page.evaluate(() => window.animation.errors)).toEqual([]);
  expect(browserErrors).toEqual([]);
});

test('FFmpeg exports an actual MP4', async ({page}) => {
  await page.goto('/tests/harness.html');
  await page.waitForFunction(() => window.animation?.ready);
  await page.evaluate(() => window.animation.render(1));
  expect((await stat('output/attached-smoke-test.mp4')).size).toBeGreaterThan(10_000);
});
