import {makeScene2D} from '@motion-canvas/2d';
import {all, chain} from '@motion-canvas/core';
import {C, connection, frame, label, packet, pill, play, reveal, terminal} from '../components';
import {COMMANDS} from '../storyboard';

export default makeScene2D(function* (view) {
  const stage = frame(view, 1);
  const local = terminal('CLIENT  /  your laptop', [-430, 10], 800, 310, C.cyan);
  const remote = terminal('PUBLISHER  /  office', [430, 10], 800, 310, C.lime);
  const transfer = connection([[-570, 188], [-570, 241], [570, 241], [570, 188]], C.purple, true);
  const bundle = pill('PUBLISH-ONLY BUNDLE', [0, 241], C.purple, 330);
  bundle.opacity(0);
  const protectedData = pill('ENCRYPTED AT REST', [-430, -183], C.cyan, 260);
  protectedData.opacity(0);
  const serving = pill('SSH ENABLED FOR THE CONSUMER', [430, -183], C.lime, 410);
  serving.opacity(0);
  const limitation = label('Publish credentials ≠ consumer identity or SSH permission', 0, 321, 23, C.muted);
  limitation.opacity(0);
  stage.body.add([transfer, local.node, remote.node, bundle, protectedData, serving, limitation]);
  yield* play(stage,
    chain(
      all(reveal(local.node), reveal(remote.node)),
      local.text.text(`$ ${COMMANDS.create}\n\nlocal credentials protected`, 1.1),
      reveal(protectedData),
    ),
    chain(
      local.text.text(`$ ${COMMANDS.create}\n$ ${COMMANDS.publish}\n\ncopy bundle → transfer privately`, 1.2),
      transfer.end(1, 0.8),
      all(reveal(bundle), reveal(limitation), packet(stage.body, transfer, C.purple)),
    ),
    chain(
      remote.text.text(`$ ${COMMANDS.serve}\n\npaste publish bundle when prompted\nkeep this process running`, 1.5),
      reveal(serving),
    ),
  );
});
