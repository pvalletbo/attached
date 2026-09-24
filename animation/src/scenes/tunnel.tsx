import {makeScene2D, Rect} from '@motion-canvas/2d';
import {all, chain} from '@motion-canvas/core';
import {C, connection, frame, label, lock, machine, packet, pill, play, reveal} from '../components';

export default makeScene2D(function* (view) {
  const stage = frame(view, 3);
  const client = machine('Client', 'PRIVATE IDENTITY', [-640, 15], C.cyan);
  const publisher = machine('Publisher', 'PUBLIC-KEY ENDPOINT', [640, 15], C.lime);
  const direct = connection([[-439, 15], [439, 15]], C.cyan);
  const directLabel = pill('DIRECT / NAT TRAVERSAL', [0, -42], C.cyan, 340);
  directLabel.opacity(0);
  const relayPath = connection([[-439, 45], [-360, 45], [-275, 210], [275, 210], [360, 45], [439, 45]], C.purple);
  const relay = new Rect({position: [0, 210], width: 218, height: 82, radius: 18, fill: C.panel, stroke: C.purple, lineWidth: 2, opacity: 0});
  relay.add(label('Iroh relay', 0, 0, 26, C.purple));
  const encrypted = pill('END-TO-END ENCRYPTED QUIC', [0, 311], C.lime, 440);
  encrypted.opacity(0);
  const admission = pill('CHECK: AUTHORIZED CONSUMER IDENTITY', [0, -171], C.lime, 590);
  admission.opacity(0);
  const relayNote = label('Fallback path · relay cannot read the tunnel', 0, 139, 21, C.muted);
  relayNote.opacity(0);
  stage.body.add([direct, relayPath, client, publisher, directLabel, relay, encrypted, admission, relayNote]);
  yield* play(stage,
    chain(
      all(reveal(client), reveal(publisher)),
      all(direct.end(1, 1), reveal(directLabel), reveal(encrypted)),
      packet(stage.body, direct, C.cyan),
    ),
    chain(
      all(direct.opacity(0.16, 0.5), directLabel.opacity(0.25, 0.5)),
      all(relayPath.end(1, 1), reveal(relay), reveal(relayNote)),
      packet(stage.body, relayPath, C.purple),
    ),
    chain(
      reveal(admission),
      publisher.stroke(C.lime, 0.5),
      packet(stage.body, relayPath, C.lime),
    ),
  );
});
