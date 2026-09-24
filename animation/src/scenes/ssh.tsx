import {makeScene2D, Rect} from '@motion-canvas/2d';
import {all, chain} from '@motion-canvas/core';
import {C, connection, frame, label, lock, packet, pill, play, reveal} from '../components';

export default makeScene2D(function* (view) {
  const stage = frame(view, 4);
  const envelope = new Rect({position: [0, 10], width: 1660, height: 370, radius: 28, fill: '#0c1821', stroke: C.cyan, lineWidth: 2, opacity: 0});
  envelope.add(label('INSIDE THE IROH TUNNEL', 0, -146, 18, C.cyan));
  stage.body.add(envelope);
  const checks = [
    ['01', 'Tunnel capability', 'Prove possession of the secret.', C.cyan],
    ['02', 'Client SSH key', 'Scoped to this connection.', C.lime],
    ['03', 'Pinned host identity', 'Verify the publisher’s SSH key.', C.purple],
  ];
  const cards = checks.map(([number, title, detail, color], index) => {
    const card = new Rect({position: [-550 + index * 550, 38], width: 460, height: 210, radius: 20, fill: C.panel, stroke: C.border, lineWidth: 2, opacity: 0});
    card.add(label(number, -181, -63, 20, color));
    card.add(lock([166, -57], color));
    card.add(label(title, 0, 7, 28, color));
    card.add(label(detail, 0, 64, 21, C.muted));
    return card;
  });
  const first = connection([[-310, 38], [-242, 38]], C.lime);
  const second = connection([[242, 38], [310, 38]], C.purple);
  stage.body.add([first, second, ...cards]);
  const shell = pill('AUTHORIZED SHELL → PUBLISHER’S OS USER', [0, 270], C.lime, 660);
  shell.opacity(0);
  const warning = label('Remote-shell-equivalent access. Not a restricted session viewer.', 0, 326, 22, C.amber);
  warning.opacity(0);
  stage.body.add([shell, warning]);
  yield* play(stage,
    chain(reveal(envelope), reveal(cards[0]), cards[0].stroke(C.cyan, 0.5)),
    chain(
      all(first.end(1, 0.5), reveal(cards[1])),
      all(second.end(1, 0.5), reveal(cards[2])),
      all(cards[1].stroke(C.lime, 0.5), cards[2].stroke(C.purple, 0.5)),
    ),
    chain(reveal(shell), reveal(warning)),
  );
});
