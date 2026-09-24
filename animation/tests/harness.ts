import {Player, Renderer, RendererResult, Stage, Vector2} from '@motion-canvas/core';
import {Scene2D, Txt} from '@motion-canvas/2d';
import project from '../src/project?project';
import {VIDEO} from '../src/storyboard';

// Both browser tests and the headless MP4 renderer use the real Motion Canvas project.
await Promise.all([
  document.fonts.load('400 28px Inter'),
  document.fonts.load('600 64px Inter'),
  document.fonts.load('400 22px "JetBrains Mono"'),
]);
await document.fonts.ready;

const errors: string[] = [];
project.logger.onLogged.subscribe(entry => {
  if (entry.level === 'error' || entry.level === 'warn') errors.push(entry.message);
});
const settings = {...project.meta.getFullPreviewSettings(), fps: VIDEO.fps, size: new Vector2(VIDEO.width, VIDEO.height)};
const stage = new Stage();
stage.configure({...settings, colorSpace: 'srgb'});
document.body.append(stage.finalBuffer);
const player = new Player(project, settings);

function snapshot() {
  const scene = player.playback.currentScene as Scene2D;
  const texts = scene.getView().findAll(node => node instanceof Txt)
    .filter(node => node.absoluteOpacity() > 0.9 && node.text().length > 0)
    .map(node => {
      const box = node.cacheBBox().transform(node.localToWorld());
      return {text: node.text(), left: box.left, right: box.right, top: box.top, bottom: box.bottom};
    });
  return {scene: scene.name, frame: player.playback.frame, texts};
}

type Snapshot = ReturnType<typeof snapshot>;
let pending: {frame: number; resolve: (snapshot: Snapshot) => void} | undefined;
const api = {
  ready: false,
  errors,
  get duration() {return player.onDurationChanged.current / VIDEO.fps;},
  async seek(seconds: number): Promise<Snapshot> {
    const frame = Math.round(seconds * VIDEO.fps);
    return new Promise(resolve => {
      pending = {frame, resolve};
      player.requestSeek(frame);
      player.requestRender();
    });
  },
  async render(seconds?: number) {
    player.deactivate();
    const renderer = new Renderer(project);
    const result = {value: RendererResult.Error};
    renderer.onFinished.subscribe(value => {result.value = value;});
    await renderer.render({
      ...project.meta.getFullRenderingSettings(),
      name: seconds ? 'attached-smoke-test' : 'attached-explained',
      range: [0, seconds ?? Infinity],
      fps: VIDEO.fps,
    });
    if (result.value !== RendererResult.Success || errors.length > 0) {
      throw new Error(`Render failed: ${result.value}; ${errors.join('; ')}`);
    }
    return result.value;
  },
};
player.onRecalculated.subscribe(() => {api.ready = true;});
player.onRender.subscribe(async () => {
  await stage.render(player.playback.currentScene, player.playback.previousScene);
  if (pending && player.playback.frame === pending.frame) {
    const {resolve} = pending;
    pending = undefined;
    resolve(snapshot());
  }
});

window.animation = api;
declare global {
  interface Window {animation: typeof api;}
}
