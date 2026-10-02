import {makeScene2D, Node, Rect} from '@motion-canvas/2d';
import {all, chain} from '@motion-canvas/core';
import {C, frame, label, leftText, pill, play, reveal, terminal} from '../components';
import {COMMANDS} from '../storyboard';

export default makeScene2D(function* (view) {
  const stage = frame(view, 5);
  const commands = new Node({});
  const exporter = terminal('TERMINAL A  /  keep running', [0, -105], 1660, 148, C.cyan);
  exporter.text.fontSize(25);
  exporter.text.y(-1);
  const herdr = terminal('TERMINAL B  /  your workflow', [0, 108], 1660, 236, C.lime);
  herdr.text.fontSize(25);
  commands.add([exporter.node, herdr.node]);
  stage.body.add(commands);
  const session = new Rect({position: [0, 11], width: 1660, height: 380, radius: 22, fill: C.panel, stroke: C.border, lineWidth: 2, opacity: 0});
  session.add(leftText('HERDR  /  Office', -790, -144, 23, C.lime));
  session.add(leftText('Illustrative session view', 480, -144, 17, C.muted));
  session.add(new Rect({position: [-567, 16], width: 436, height: 212, radius: 14, fill: C.bg, stroke: C.border, lineWidth: 1}));
  session.add(leftText('REMOTE MACHINE', -755, -48, 16, C.muted));
  session.add(leftText('●  Office', -755, 9, 28, C.lime));
  session.add(leftText('attached-office', -755, 57, 19, C.muted));
  session.add(leftText('Session / project', -287, -52, 25));
  session.add(leftText('$ working where the code lives', -287, 8, 25, C.cyan));
  session.add(leftText('Your terminal. Your tools. The remote machine.', -287, 66, 24, C.muted));
  const summary = pill('DISCOVER  →  CONNECT  →  AUTHORIZE  →  WORK', [0, 288], C.lime, 720);
  summary.opacity(0);
  const caution = new Node({opacity: 0});
  caution.add(label('Stop attached serve on each publisher to end SSH access.', 0, 262, 27, C.amber));
  caution.add(label('Detached processes may remain. General token revocation is not implemented.', 0, 313, 22, C.muted));
  stage.body.add([session, summary, caution]);
  yield* play(stage,
    chain(
      all(reveal(exporter.node), reveal(herdr.node)),
      exporter.text.text(`$ ${COMMANDS.exportSsh}`, 1),
      herdr.text.text(`$ ${COMMANDS.addMachine}\n$ ${COMMANDS.herdr}`, 1.8),
    ),
    chain(commands.opacity(0, 0.5), reveal(session), reveal(summary)),
    chain(summary.opacity(0, 0.4), reveal(caution)),
  );
});
