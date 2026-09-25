import {makeScene2D, Rect} from '@motion-canvas/2d';
import {all, chain, waitFor} from '@motion-canvas/core';
import {C, connection, frame, infoCard, label, lock, machine, packet, pill, play, reveal} from '../components';

export default makeScene2D(function* (view) {
  const stage = frame(view, 0);
  const local = machine('Your laptop', 'CLIENT / HERDR', [-620, 10], C.cyan);
  const remote = machine('Your remote machine', 'PUBLISHER / OFFICE', [620, 10], C.lime);
  const bridge = new Rect({position: [0, 10], width: 330, height: 254, radius: 24, fill: C.panel, stroke: C.lime, lineWidth: 2, opacity: 0});
  bridge.add(lock([0, -66]));
  bridge.add(label('Attached', 0, 5, 39));
  bridge.add(label('discovery + transport', 0, 65, 20, C.muted));
  const left = connection([[-425, 10], [-180, 10]]);
  const right = connection([[180, 10], [425, 10]], C.lime);
  stage.body.add([left, right, local, remote, bridge]);
  const benefits = [
    infoCard('No open SSH port', 'No inbound SSH port to expose.', [-570, 262], C.cyan, 510),
    infoCard('No manual SSH key setup', 'Connection-scoped client keys.', [0, 262], C.lime, 510),
    infoCard('Your existing workflow', 'Herdr connects through SSH.', [570, 262], C.purple, 510),
  ];
  stage.body.add(benefits);
  yield* play(stage,
    chain(all(reveal(local), reveal(remote)), waitFor(0.6), reveal(bridge)),
    chain(
      all(left.end(1, 0.8), right.end(1, 0.8)),
      all(packet(stage.body, left), packet(stage.body, right)),
      all(...benefits.map(card => reveal(card))),
    ),
  );
});
