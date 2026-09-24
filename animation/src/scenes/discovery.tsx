import {makeScene2D, Rect} from '@motion-canvas/2d';
import {all, chain} from '@motion-canvas/core';
import {C, connection, frame, label, leftText, lock, machine, packet, pill, play, reveal} from '../components';

export default makeScene2D(function* (view) {
  const stage = frame(view, 2);
  const client = machine('Client', 'DOWNLOAD + DECRYPT', [-630, -58], C.cyan);
  const publisher = machine('Publisher', 'ENCRYPT + UPLOAD', [630, -58], C.lime);
  const sync = new Rect({position: [0, -58], width: 330, height: 254, radius: 24, fill: C.panel, stroke: C.purple, lineWidth: 2, opacity: 0});
  sync.add(lock([0, -72], C.purple));
  sync.add(label('Sync service', 0, 0, 31));
  sync.add(label('opaque ciphertext', 0, 55, 19, C.purple));
  const upload = connection([[433, -58], [181, -58]], C.lime, true);
  const download = connection([[-181, -58], [-433, -58]], C.cyan, true);
  const uploadLabel = label('PUBLISH', 305, -103, 16, C.lime);
  const downloadLabel = label('FETCH', -305, -103, 16, C.cyan);
  uploadLabel.opacity(0);
  downloadLabel.opacity(0);
  const descriptor = new Rect({position: [0, 222], width: 1660, height: 208, radius: 20, fill: C.panel, stroke: C.border, lineWidth: 2, opacity: 0});
  descriptor.add(leftText('INSIDE THE ENCRYPTED HOST DESCRIPTOR', -792, -67, 18, C.purple));
  const fields = [
    ['Host label', 'office'], ['Iroh endpoint ticket', 'where to reach the peer'],
    ['Tunnel capability', 'shared authorization secret'],
    ['Attached version', 'running binary version'], ['SSH-enabled status', 'access advertised'],
    ['Publication + expiration', 'validity window'],
  ];
  fields.forEach(([name, value], index) => {
    const x = -792 + (index % 3) * 540;
    const y = index < 3 ? -12 : 61;
    descriptor.add(leftText(name, x, y, 22));
    descriptor.add(leftText(value, x, y + 29, 17, C.muted));
  });
  const noProxy = pill('DISCOVERY ≠ LIVE TRAFFIC', [0, 92], C.purple, 350);
  noProxy.opacity(0);
  stage.body.add([upload, download, client, publisher, sync, uploadLabel, downloadLabel, descriptor, noProxy]);
  yield* play(stage,
    chain(
      all(reveal(client), reveal(publisher), reveal(sync), reveal(descriptor)),
      all(upload.end(1, 0.75), reveal(uploadLabel)),
      packet(stage.body, upload, C.lime),
    ),
    chain(
      all(download.end(1, 0.75), reveal(downloadLabel)),
      packet(stage.body, download, C.cyan),
      client.stroke(C.cyan, 0.5),
    ),
    chain(reveal(noProxy), sync.stroke(C.amber, 0.5)),
  );
});
