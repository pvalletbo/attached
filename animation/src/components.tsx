import {Circle, Line, Node, Rect, Txt, View2D} from '@motion-canvas/2d';
import {
  all, chain, easeOutCubic, linear, tween, waitFor,
  type ThreadGenerator,
} from '@motion-canvas/core';
import {CHAPTERS, chapterDuration} from './storyboard';

export const C = {
  bg: '#080f17', panel: '#111e2a', border: '#2c414f',
  text: '#edf4f2', muted: '#9bafba', lime: '#c6f56b',
  cyan: '#70dcea', purple: '#b6a3fc', amber: '#ffbf7a',
};
export const FONT = 'Inter';
export const MONO = 'JetBrains Mono';

type Point = [number, number];

export function label(text: string, x: number, y: number, size = 24, fill = C.text) {
  return new Txt({text, position: [x, y], fontFamily: FONT, fontSize: size, fill});
}

export function leftText(text: string, x: number, y: number, size = 24, fill = C.text) {
  return new Txt({text, position: [x, y], offset: [-1, 0], fontFamily: FONT, fontSize: size, fill});
}

export function frame(view: View2D, index: number) {
  const chapter = CHAPTERS[index];
  view.fill(C.bg);
  const root = new Node({opacity: 0});
  view.add(root);
  // Quiet graph-paper texture, drawn locally so rendering needs no remote assets.
  for (let x = -960; x <= 960; x += 80) {
    root.add(new Line({points: [[x, -540], [x, 540]], stroke: '#13212c', lineWidth: 1, opacity: 0.45}));
  }
  for (let y = -540; y <= 540; y += 80) {
    root.add(new Line({points: [[-960, y], [960, y]], stroke: '#13212c', lineWidth: 1, opacity: 0.45}));
  }
  root.add(<>
    <Rect x={-826} y={-475} width={26} height={18} radius={9} rotation={-35} stroke={C.lime} lineWidth={3}/>
    <Rect x={-812} y={-481} width={26} height={18} radius={9} rotation={-35} stroke={C.lime} lineWidth={3}/>
    <Txt x={-774} y={-478} offset={[-1, 0]} text="attached" fontFamily={FONT} fontSize={30} fontWeight={600} fill={C.text}/>
    <Txt x={830} y={-478} offset={[1, 0]} text={`HOW IT WORKS     /     ${String(index + 1).padStart(2, '0')} — 06`} fontFamily={MONO} fontSize={17} fill={C.muted}/>
    <Line points={[[-840, -440], [840, -440]]} stroke={C.border} lineWidth={1}/>
  </>);
  root.add(leftText(chapter.label, -830, -390, 19, C.lime));
  const title = leftText(chapter.title, -830, -319, 64);
  title.fontWeight(600);
  root.add(title);
  root.add(leftText(chapter.subtitle, -830, -245, 26, C.muted));
  const body = new Node({});
  const caption = label('', 0, 425, 28);
  caption.width(1570);
  caption.textWrap(true);
  caption.textAlign('center');
  caption.lineHeight(42);
  root.add(body);
  root.add(new Line({points: [[-830, 365], [830, 365]], stroke: C.border, lineWidth: 1}));
  root.add(caption);
  const segments: Line[] = [];
  for (let i = 0; i < CHAPTERS.length; i++) {
    const x = -830 + i * 280;
    root.add(new Line({points: [[x, 496], [x + 260, 496]], stroke: C.border, lineWidth: 3}));
    const segment = new Line({points: [[x, 496], [x + 260, 496]], stroke: C.lime, lineWidth: 3, end: i < index ? 1 : 0});
    root.add(segment);
    segments.push(segment);
  }
  return {root, body, caption, chapter, progress: segments[index]};
}

export type Frame = ReturnType<typeof frame>;

export function* play(stage: Frame, ...animations: ThreadGenerator[]) {
  // Each beat has a fixed dwell time. Animation cannot silently shorten reading time.
  if (animations.length !== stage.chapter.beats.length) {
    throw new Error(`Expected one animation per caption in ${stage.chapter.id}`);
  }
  yield* stage.root.opacity(1, 0.6);
  yield* all(
    stage.progress.end(1, chapterDuration(stage.chapter) - 1, linear),
    chain(...stage.chapter.beats.map((beat, index) => beatAnimation(stage, beat.caption, beat.seconds, animations[index]))),
  );
  yield* stage.root.opacity(0, 0.4);
}

function* beatAnimation(stage: Frame, caption: string, seconds: number, animation: ThreadGenerator) {
  stage.caption.text(caption);
  yield* all(waitFor(seconds), animation);
}

export function* reveal(node: Node, duration = 0.65) {
  node.opacity(0);
  node.scale(0.96);
  yield* all(node.opacity(1, duration), node.scale(1, duration, easeOutCubic));
}

export function pill(text: string, position: Point, color = C.lime, width = 280) {
  const node = new Rect({position, width, height: 44, radius: 22, fill: C.bg, stroke: color, lineWidth: 1});
  node.add(label(text, 0, 0, 17, color));
  return node;
}

export function terminal(title: string, position: Point, width = 680, height = 290, accent = C.lime) {
  const node = new Rect({position, width, height, radius: 20, fill: C.panel, stroke: C.border, lineWidth: 2, opacity: 0});
  for (let i = 0; i < 3; i++) node.add(new Circle({position: [-width / 2 + 28 + i * 20, -height / 2 + 28], size: 8, fill: i === 0 ? accent : C.border}));
  node.add(leftText(title, -width / 2 + 94, -height / 2 + 29, 17, C.muted));
  node.add(new Line({points: [[-width / 2, -height / 2 + 56], [width / 2, -height / 2 + 56]], stroke: C.border, lineWidth: 1}));
  const text = new Txt({position: [-width / 2 + 32, -height / 2 + 92], offset: [-1, -1], text: '', fontFamily: MONO, fontSize: 22, lineHeight: 39, fill: accent});
  node.add(text);
  return {node, text};
}

export function machine(title: string, role: string, position: Point, accent = C.cyan) {
  const node = new Rect({position, width: 380, height: 254, radius: 24, fill: C.panel, stroke: C.border, lineWidth: 2, opacity: 0});
  node.add(<>
    <Rect y={-59} width={90} height={55} radius={8} stroke={accent} lineWidth={3}/>
    <Line points={[[-55, -21], [55, -21]]} stroke={accent} lineWidth={3} lineCap="round"/>
    <Txt y={25} text={title} fontFamily={FONT} fontSize={32} fontWeight={600} fill={C.text}/>
    <Txt y={77} text={role} fontFamily={MONO} fontSize={17} fill={accent}/>
  </>);
  return node;
}

export function connection(points: Point[], color = C.cyan, dashed = false) {
  return new Line({points, stroke: color, lineWidth: 4, radius: 30, lineCap: 'round', lineJoin: 'round', endArrow: true, arrowSize: 13, end: 0, lineDash: dashed ? [10, 12] : []});
}

export function* packet(parent: Node, path: Line, color = C.lime, reverse = false) {
  const dot = new Circle({size: 15, fill: color, shadowColor: color, shadowBlur: 18});
  parent.add(dot);
  yield* tween(1.25, value => {
    dot.position(path.getPointAtPercentage(reverse ? 1 - value : value).position);
  });
  dot.remove();
}

export function lock(position: Point, color = C.lime) {
  const node = new Node({position});
  node.add(<>
    <Line points={[[-14, -4], [-14, -25], [14, -25], [14, -4]]} radius={14} stroke={color} lineWidth={4}/>
    <Rect y={9} width={46} height={36} radius={8} fill={C.panel} stroke={color} lineWidth={3}/>
    <Circle y={9} size={7} fill={color}/>
  </>);
  return node;
}

export function infoCard(title: string, detail: string, position: Point, color = C.cyan, width = 460) {
  const node = new Rect({position, width, height: 140, radius: 18, fill: C.panel, stroke: C.border, lineWidth: 2, opacity: 0});
  node.add(leftText(title, -width / 2 + 28, -27, 25, color));
  node.add(leftText(detail, -width / 2 + 28, 29, 20, C.muted));
  return node;
}
