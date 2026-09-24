// A separate edit, not a reskin: short cuts, poster typography, and paper scraps.
// Captions carry the explanation without requiring a voiceover or music.
export const SHOTS = [
  {id: 'distance', seconds: 5, headline: "YOU'RE HERE.", caption: 'Your laptop is here. The machine you want to work on is somewhere else.'},
  {id: 'intro', seconds: 5, headline: 'attached.', caption: 'Attached connects Herdr to that machine. No open inbound SSH port needed.'},
  {id: 'bundle', seconds: 10, headline: 'PASS A NOTE.', caption: 'Create an account. Transfer a publish-only bundle privately. Paste it when serve prompts; keep serve running.'},
  {id: 'directory', seconds: 9, headline: 'THE CLOUD GETS', caption: 'The publisher uploads an encrypted host descriptor. The client fetches and decrypts it. Sync cannot read or forge it.'},
  {id: 'direct', seconds: 7, headline: 'TRY THE SHORTCUT.', caption: 'Iroh uses public-key endpoint identities and attempts NAT traversal for a direct, end-to-end encrypted QUIC connection.'},
  {id: 'relay', seconds: 7, headline: 'TAKE THE LONG WAY.', caption: 'If direct connectivity fails, Iroh uses a relay. The relay still cannot read the end-to-end encrypted tunnel.'},
  {id: 'checks', seconds: 9, headline: 'NOT JUST ANYONE.', caption: 'Attached checks the consumer Iroh identity before admitting traffic. SSH adds a capability, a connection-scoped key, and host pinning.'},
  {id: 'work', seconds: 10, headline: 'LESS NETWORKING.', caption: 'Keep export-ssh-config running. In another terminal, add the machine and open Herdr. Herdr manages sessions over SSH.'},
  {id: 'warning', seconds: 9, headline: 'REAL SHELL.', caption: 'Access runs as the publisher’s OS user. Protect owner/download bundles. Stop serve on each publisher to end SSH access.'},
  {id: 'outro', seconds: 4, headline: 'STAY ATTACHED.', caption: 'Your terminal. A different machine. Back to work.'},
] as const;

export const ZINE_DURATION = SHOTS.reduce((sum, shot) => sum + shot.seconds, 0);
export type Shot = typeof SHOTS[number];
