import {Circle, makeScene2D, Rect, Video} from '@motion-canvas/2d';
import padlockClip from '../assets/blender-padlock.mp4';
import {all, chain, waitFor} from '@motion-canvas/core';
import {COMMANDS} from '../storyboard';
import {ACID, BLUE, INK, PAPER, RED, arrow, cut, laptop, line, scrap, sheet, shout, slam, stamp, travel, type} from './art';
import {SHOTS} from './script';

export default makeScene2D(function* (view) {
  // 01: An asymmetric poster, not a title slide.
  {
    const s = sheet(view, SHOTS[0]);
    const here = shout(s.shot.headline, [-330, -306], 153);
    here.rotation(-3);
    const there = shout("CODE'S THERE.", [333, -125], 136, BLUE);
    there.rotation(3);
    const local = laptop([-589, 89], 'YOU', -5);
    const remote = laptop([588, 112], 'THE OTHER MACHINE', 5, BLUE);
    const path = arrow([[-365, 143], [-224, 98], [-100, 185], [60, 124], [174, 170], [365, 124]], RED);
    s.body.add([here, there, local, remote, path]);
    yield* cut(s, chain(slam(here), slam(there), all(slam(local), slam(remote)), path.end(1, 0.65), travel(s.body, path)));
  }

  // 02: Oversized type lands like a wheat-pasted gig poster.
  {
    const s = sheet(view, SHOTS[1], INK, PAPER);
    const title = shout(s.shot.headline, [0, -108], 330, PAPER);
    const sticker = stamp('NO OPEN SSH PORT.', [228, 207], RED, -8, 610);
    const note = type('Herdr on your laptop. Work on the remote machine.', [0, -360], 30, PAPER);
    const underline = line([[-666, 82], [-281, 66], [234, 89], [637, 61]], ACID, 14);
    underline.end(0);
    s.body.add([note, title, underline, sticker]);
    yield* cut(s, chain(slam(title), underline.end(1, 0.5), slam(sticker), waitFor(1), sticker.rotation(-4, 0.3)));
  }

  // 03: Two taped scraps, with the actual commands kept readable.
  {
    const s = sheet(view, SHOTS[2], BLUE, PAPER);
    s.body.add(shout(s.shot.headline, [0, -325], 142, PAPER));
    s.body.add(type('A publish-only bundle is NOT a consumer login.', [0, -196], 28, PAPER));
    const local = scrap([-355, 70], 935, 365, -3);
    local.add(type('YOUR LAPTOP', [-258, -126], 25, BLUE));
    const localText = type('', [-425, -68], 23);
    localText.offset([-1, -1]);
    local.add(localText);
    const remote = scrap([515, 93], 635, 330, 4, ACID);
    remote.add(type('REMOTE MACHINE', [0, -100], 25));
    const remoteText = type('', [-280, -54], 22);
    remoteText.offset([-1, -1]);
    remote.add(remoteText);
    const note = type('Local secrets: encrypted at rest with your encryption password.', [0, 329], 23, PAPER);
    const path = arrow([[113, 75], [159, 43], [198, 72]], PAPER);
    s.body.add([local, remote, note, path]);
    yield* cut(s, chain(
      slam(local),
      localText.text(`$ ${COMMANDS.create}\n$ ${COMMANDS.publish}\n\ncopy → transfer privately`, 1.7),
      slam(remote), path.end(1, 0.5),
      remoteText.text(`$ ${COMMANDS.serve}\n\npaste bundle when prompted\nleave serve running`, 1.7),
    ));
  }

  // 04: A literal ciphertext collage. The directory never becomes the live tunnel.
  {
    const s = sheet(view, SHOTS[3], RED);
    s.body.add(shout(s.shot.headline, [0, -333], 130));
    const gibberish = shout('GIBBERISH.', [0, -153], 197, PAPER);
    const labels = [['PUBLISHER', 'encrypt'], ['SYNC', 'a8f0:??:19ce'], ['CLIENT', 'decrypt']];
    const scraps = labels.map(([name, detail], i) => {
      const card = scrap([-620 + i * 620, 129], 420, 176, i === 1 ? 3 : -3);
      card.add(shout(name, [0, -36], 45));
      card.add(type(detail, [0, 38], 27, i === 1 ? BLUE : INK));
      return card;
    });
    const upload = arrow([[-392, 112], [-307, 100], [-235, 127]]);
    const download = arrow([[233, 130], [314, 104], [391, 122]]);
    s.body.add([gibberish, upload, download, ...scraps]);
    s.body.add(type('host descriptor ≠ terminal traffic', [0, 278], 29));
    s.body.add(type('Sync can hide records or replay valid ones until expiration.', [0, 338], 22));
    yield* cut(s, chain(
      slam(gibberish), all(...scraps.map(card => slam(card))),
      upload.end(1, 0.5), travel(s.body, upload, BLUE),
      download.end(1, 0.5), travel(s.body, download, BLUE),
    ));
  }

  // 05–06: Match-cut the same peers; redraw only the route between them.
  for (const relay of [false, true]) {
    const s = sheet(view, SHOTS[relay ? 5 : 4], PAPER);
    const title = shout(s.shot.headline, [0, -295], relay ? 121 : 136);
    const local = laptop([-650, 20], 'CLIENT', -4);
    const remote = laptop([650, 20], 'PUBLISHER', 4);
    const direct = arrow([[-439, 5], [-248, -8], [58, 7], [439, -6]], BLUE);
    const route = arrow([[-439, 5], [-329, 5], [-226, 230], [237, 230], [328, -6], [439, -6]], BLUE);
    s.body.add([title, direct, route, local, remote]);
    s.body.add(type('END-TO-END ENCRYPTED / QUIC', [0, -158], 27, BLUE));
    if (relay) {
      direct.end(1);
      direct.opacity(0.2);
      const cross = line([[-80, -48], [80, 48], [0, 0], [75, -51], [-81, 47]], RED, 9);
      const circle = new Circle({position: [0, 230], size: [244, 103], fill: ACID, stroke: INK, lineWidth: 4});
      const relayLabel = type('RELAY', [0, 230], 32);
      const blind = stamp('STILL CANNOT READ IT.', [0, 334], BLUE, -2, 560);
      s.body.add([cross, circle, relayLabel, blind]);
      yield* cut(s, chain(
        all(slam(title), slam(local), slam(remote)), route.end(1, 0.7),
        travel(s.body, route), slam(blind), travel(s.body, route),
      ));
    } else {
      s.body.add(type('Try NAT traversal. Skip the manual IP juggling.', [0, 321], 26));
      yield* cut(s, chain(
        all(slam(title), slam(local), slam(remote)), direct.end(1, 0.7),
        travel(s.body, direct), travel(s.body, direct), travel(s.body, direct),
      ));
    }
  }

  // 07: A bouncer's checklist rather than a row of enterprise security cards.
  {
    const s = sheet(view, SHOTS[6], INK, PAPER);
    s.body.add(shout(s.shot.headline, [0, -313], 137, PAPER));
    const checklist = scrap([-310, 57], 1050, 410, -2);
    // A real Blender render, composited by Motion Canvas and synced to its clock.
    const padlock = new Video({
      src: padlockClip, position: [575, -3], size: 460, loop: true, play: true,
    });
    const lines = [
      'Authorized consumer Iroh identity',
      'Tunnel capability',
      'Connection-scoped client SSH key',
      'Pinned publisher SSH host key',
    ];
    const checks = lines.map((text, i) => {
      const y = -131 + i * 87;
      const item = type(text, [-460, y], 27);
      item.offset([-1, 0]);
      checklist.add(item);
      const tick = line([[437, y], [451, y + 14], [482, y - 22]], BLUE, 7);
      tick.end(0);
      checklist.add(tick);
      return tick;
    });
    const approved = stamp('YOU CAN COME IN.', [535, 270], RED, -5, 485);
    s.body.add([checklist, padlock, approved]);
    s.body.add(type('Identity first. Application traffic second.', [0, 329], 27, ACID));
    yield* cut(s, chain(slam(checklist), ...checks.map(tick => tick.end(1, 0.65)), slam(approved)));
    padlock.pause();
  }

  // 08: Terminal type, at full size, without simulated product chrome.
  {
    const s = sheet(view, SHOTS[7], ACID);
    s.body.add(shout(s.shot.headline, [0, -337], 143));
    s.body.add(shout('MORE DOING.', [336, -169], 123, BLUE));
    const terminal = new Rect({position: [0, 139], width: 1675, height: 355, fill: INK, rotation: -1, opacity: 0});
    const commands = type('', [-789, -131], 25, PAPER);
    commands.offset([-1, -1]);
    terminal.add(commands);
    s.body.add(terminal);
    yield* cut(s, chain(
      slam(terminal),
      commands.text(`# terminal A — keep running\n$ ${COMMANDS.exportSsh}\n\n# terminal B\n$ ${COMMANDS.addMachine}\n$ ${COMMANDS.herdr}`, 3),
    ));
  }

  // 09: Keep the caveat. Punk styling is not a reason to oversell security.
  {
    const s = sheet(view, SHOTS[8], RED);
    s.body.add(shout(s.shot.headline, [-306, -322], 177));
    const second = shout('REAL RESPONSIBILITY.', [0, -124], 126, PAPER);
    const warning = scrap([0, 153], 1640, 317, -1);
    warning.add(type('Owner/download bundles = remote-shell-equivalent secrets.', [0, -98], 27));
    warning.add(type('Stop attached serve on EACH publisher to end SSH access.', [0, -27], 27));
    warning.add(type('Detached processes may remain. General token revocation is not implemented.', [0, 43], 23));
    warning.add(type('Herdr manages sessions over SSH; Attached does not publish their names.', [0, 106], 23));
    s.body.add([second, warning]);
    yield* cut(s, chain(slam(second), slam(warning)));
  }

  // 10: A sign-off, not a sales CTA. Hold it as the final frame.
  {
    const s = sheet(view, SHOTS[9], BLUE, PAPER);
    const title = shout(s.shot.headline, [0, -94], 213, PAPER);
    title.rotation(-4);
    const underline = line([[-766, 100], [-195, 72], [226, 94], [749, 67]], ACID, 15);
    underline.end(0);
    s.body.add([title, underline, type('attached.sh', [346, 247], 49, PAPER)]);
    yield* cut(s, chain(slam(title), underline.end(1, 0.6)), true);
  }
});
