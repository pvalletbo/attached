import {expect, test} from '@playwright/test';
import {stat} from 'node:fs/promises';
import {SHOTS} from '../src/zine/script';
import type {} from './harness';

const checksStart = SHOTS.slice(0, SHOTS.findIndex(shot => shot.id === 'checks'))
  .reduce((sum, shot) => sum + shot.seconds, 0);

test('Blender insert is a small, bundled asset', async () => {
  const clip = await stat('src/assets/blender-padlock.mp4');
  expect(clip.size).toBeGreaterThan(10_000);
  expect(clip.size).toBeLessThan(1_000_000);
});

test('Blender clip plays, loops, and seeks with the Motion Canvas timeline', async ({page}, testInfo) => {
  await page.goto('/tests/harness.html?style=zine');
  await page.waitForFunction(() => window.animation?.ready);
  const early = await page.evaluate(time => window.animation.seek(time), checksStart + 0.5);
  expect(early.videos).toHaveLength(1);
  expect(early.videos[0].src).toContain('blender-padlock.mp4');
  expect(early.videos[0].duration).toBeCloseTo(3, 1);
  expect(early.videos[0].time).toBeCloseTo(0.5, 1);
  expect(early.videos[0].playing).toBe(true);
  // Crop only the embedded footage: not the changing caption, checklist, or progress bar.
  const clip = {x: 1330, y: 315, width: 400, height: 430};
  const front = await page.screenshot({clip, path: testInfo.outputPath('blender-front.png')});
  await page.evaluate(time => window.animation.seek(time), checksStart + 1.5);
  const back = await page.screenshot({clip, path: testInfo.outputPath('blender-back.png')});
  expect(front.equals(back), 'The actual video pixels should rotate, not just its node clock.').toBe(false);
  const looped = await page.evaluate(time => window.animation.seek(time), checksStart + 3.5);
  expect(looped.videos[0].time).toBeCloseTo(0.5, 1);
  await page.evaluate(time => window.animation.seek(time), checksStart + 0.5);
  expect((await page.screenshot({clip})).equals(front), 'Backward seeking should restore the same decoded frame.').toBe(true);
  const after = await page.evaluate(time => window.animation.seek(time), checksStart + 9.5);
  expect(after.videos).toHaveLength(0);
  expect(await page.evaluate(() => window.animation.errors)).toEqual([]);
});
