// The captions are the script: the film is intentionally readable without audio.
// Architecture and commands follow the repository README and crates/cli/src/ssh.
export const VIDEO = {width: 1920, height: 1080, fps: 30} as const;
export const TRANSITION_SECONDS = 1;

export const COMMANDS = {
  create: 'attached account create',
  publish: 'attached account export --type publish',
  serve: 'attached serve --host-label office',
  exportSsh: 'attached export-ssh-config',
  addMachine: 'herdr machine add attached-office --label Office',
  herdr: 'herdr',
} as const;

export interface Beat {
  seconds: number;
  caption: string;
}
export interface Chapter {
  id: string;
  label: string;
  title: string;
  subtitle: string;
  beats: readonly Beat[];
}

export const CHAPTERS: readonly Chapter[] = [
  {
    id: 'overview', label: 'THE IDEA',
    title: 'Far away. One connection.',
    subtitle: 'Attached connects your local Herdr to a remote machine — without an open SSH port.',
    beats: [
      {seconds: 5, caption: 'Your terminal is here. Your work can be somewhere else.'},
      {seconds: 7, caption: 'Attached handles discovery and secure transport. Herdr manages the remote sessions over SSH.'},
    ],
  },
  {
    id: 'setup', label: '01 / SHARE ACCESS',
    title: 'One account. Two different roles.',
    subtitle: 'The client consumes access. The publisher offers its current OS account.',
    beats: [
      {seconds: 6, caption: 'Create an account on the client. A local encryption password protects sensitive data at rest.'},
      {seconds: 6, caption: 'Transfer a publish-only bundle out of band. It does not grant consumer access.'},
      {seconds: 7, caption: 'Paste the bundle when serve prompts. SSH is enabled for the authorized consumer; keep serve running.'},
    ],
  },
  {
    id: 'discovery', label: '02 / FIND THE MACHINE',
    title: 'A directory, not a doorway.',
    subtitle: 'The synchronization service stores encrypted host descriptors — not your terminal traffic.',
    beats: [
      {seconds: 6, caption: 'The publisher encrypts and authenticates a descriptor, then uploads it to the sync service.'},
      {seconds: 6, caption: 'The client downloads and decrypts it with account credentials shared out of band.'},
      {seconds: 7, caption: 'The service cannot read or forge descriptors. It can hide them or replay valid records until expiration.'},
    ],
  },
  {
    id: 'tunnel', label: '03 / CROSS THE NETWORK',
    title: 'Peer to peer. Encrypted end to end.',
    subtitle: 'Iroh identifies endpoints by public key and carries the tunnel over QUIC.',
    beats: [
      {seconds: 6, caption: 'Iroh attempts NAT traversal to connect the client and publisher directly.'},
      {seconds: 6, caption: 'When a direct path is unavailable, Iroh falls back to a relay. Encryption still ends only at the peers.'},
      {seconds: 6, caption: 'Attached checks the authorized consumer’s Iroh identity before admitting application traffic.'},
    ],
  },
  {
    id: 'ssh', label: '04 / AUTHORIZE THE SHELL',
    title: 'A tunnel is only the beginning.',
    subtitle: 'SSH adds authorization and host verification inside the Iroh connection.',
    beats: [
      {seconds: 6, caption: 'The client presents the tunnel capability from the encrypted descriptor.'},
      {seconds: 6, caption: 'Attached uses a connection-scoped client SSH key and pins the publisher’s SSH host identity.'},
      {seconds: 6, caption: 'The authorized client can execute commands as the publisher’s current OS user. This is real shell access.'},
    ],
  },
  {
    id: 'workflow', label: '05 / GET BACK TO WORK',
    title: 'Now it feels like a local workflow.',
    subtitle: 'Expose an SSH alias, add the machine to Herdr, and connect.',
    beats: [
      {seconds: 7, caption: 'Keep export-ssh-config running in one terminal. Add the machine and launch Herdr from another.'},
      {seconds: 6, caption: 'Herdr discovers and manages sessions over SSH. Attached does not publish session names.'},
      {seconds: 8, caption: 'Treat owner/download bundles like remote-shell secrets. Stop serve on each publisher to end SSH access.'},
    ],
  },
];

export function chapterDuration(chapter: Chapter): number {
  return TRANSITION_SECONDS + chapter.beats.reduce((total, beat) => total + beat.seconds, 0);
}

export const DURATION_SECONDS = CHAPTERS.reduce((total, chapter) => total + chapterDuration(chapter), 0);
