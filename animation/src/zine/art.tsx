import {Circle, Line, Node, Rect, Txt, View2D} from '@motion-canvas/2d';
import {all, easeOutBack, easeOutCubic, linear, tween, waitFor, type ThreadGenerator} from '@motion-canvas/core';
import type {Shot} from './script';

export const INK = '#20201e';
export const PAPER = '#eee9da';
export const RED = '#eb4b2f';
export const BLUE = '#3455cc';
export const ACID = '#dfff70';
export type Point = [number, number];

export function type(text: string, position: Point, size = 32, fill = INK) {
  return new Txt({text, position, fontFamily: 'JetBrains Mono', fontSize: size, fill, lineHeight: size * 1.5});
}

export function shout(text: string, position: Point, size = 126, fill = INK) {
  return new Txt({text, position, fontFamily: 'Anton', fontSize: size, lineHeight: size * 1.1, fill});
}

export function line(points: Point[], color = INK, width = 5) {
  return new Line({points, stroke: color, lineWidth: width, lineCap: 'round', lineJoin: 'round'});
}

export function arrow(points: Point[], color = INK) {
  const path = line(points, color, 6);
  path.endArrow(true);
  path.arrowSize(21);
  path.end(0);
  return path;
}

export function stamp(text: string, position: Point, color = RED, rotation = -5, width = 540) {
  const node = new Rect({position, rotation, width, height: 91, fill: color, opacity: 0});
  node.add(type(text, [0, 0], 30, PAPER));
  return node;
}

export function scrap(position: Point, width: number, height: number, rotation = 0, fill = PAPER) {
  const points: Point[] = [[-width / 2, -height / 2], [width / 2, -height / 2]];
  // Torn, not rounded. The pattern is deterministic when scrubbing/exporting.
  for (let y = -height / 2; y < height / 2; y += 27) points.push([width / 2 + (Math.floor(y) % 3) * 3, y]);
  points.push([width / 2, height / 2]);
  for (let x = width / 2; x > -width / 2; x -= 29) points.push([x, height / 2 + (Math.floor(x) % 4) * 2]);
  points.push([-width / 2, height / 2]);
  const node = new Node({position, rotation, opacity: 0});
  node.add(new Line({points, closed: true, fill, stroke: INK, lineWidth: 2, shadowColor: '#00000035', shadowBlur: 0, shadowOffset: [9, 12]}));
  node.add(new Rect({position: [width * 0.1, -height / 2 + 2], rotation: -4, width: 130, height: 28, fill: '#d8ceafa0'}));
  return node;
}

export function laptop(position: Point, text: string, rotation = 0, color = INK) {
  const node = new Node({position, rotation, opacity: 0});
  node.add(line([[-140, -91], [135, -97], [143, 84], [-139, 88], [-140, -91]], color));
  node.add(line([[-139, 88], [-184, 116], [181, 112], [143, 84]], color));
  node.add(type('>_', [0, -16], 78, color));
  node.add(type(text, [0, 177], 27, color));
  return node;
}

export function* slam(node: Node, angle = node.rotation(), duration = 0.36) {
  node.opacity(1);
  node.scale(1.17);
  node.rotation(angle - 5);
  yield* all(node.scale(1, duration, easeOutBack), node.rotation(angle, duration, easeOutCubic));
}

export function* travel(parent: Node, path: Line, color = RED) {
  const dot = new Rect({size: 19, fill: color, rotation: 20});
  parent.add(dot);
  yield* tween(0.9, progress => {
    dot.position(path.getPointAtPercentage(progress).position);
    dot.rotation(progress * 250);
  });
  dot.remove();
}

export function sheet(view: View2D, shot: Shot, background = PAPER, foreground = INK) {
  view.fill(background);
  const root = new Node({});
  view.add(root);
  // Static photocopier flecks. No strobe/glitch flicker and no remote image assets.
  for (let i = 0; i < 170; i++) {
    const x = ((i * 7919) % 1910) - 955;
    const y = ((i * 3571) % 1070) - 535;
    root.add(new Circle({position: [x, y], size: 1 + i % 3, fill: foreground, opacity: 0.1}));
  }
  root.add(type('attached / a field recording', [-571, -482], 20, foreground));
  root.add(type('PLAY >', [788, -482], 20, foreground));
  const body = new Node({});
  root.add(body);
  root.add(new Rect({y: 464, width: 1920, height: 152, fill: INK}));
  const caption = type(shot.caption, [0, 459], 27, PAPER);
  caption.width(1640);
  caption.textWrap(true);
  caption.textAlign('center');
  root.add(caption);
  const underline = line([[-850, 525], [850, 525]], RED, 4);
  underline.end(0);
  root.add(underline);
  return {root, body, underline, shot};
}

export function* cut(stage: ReturnType<typeof sheet>, animation: ThreadGenerator, last = false) {
  yield* all(waitFor(stage.shot.seconds), stage.underline.end(1, stage.shot.seconds, linear), animation);
  if (!last) stage.root.remove();
}
