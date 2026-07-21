// Short, security-forward tips surfaced one-at-a-time at startup and via /tips.
// Kept dependency-free so it can be unit-tested and reused by both modes.

export const TIPS = [
  'Run /verify <nick> to confirm a peer out-of-band — a green ✓ then appears next to their name.',
  '/invite generates a QR code + ciphermesh:// link to pull someone into your room.',
  '/ephemeral 5m makes new messages self-destruct after the timer.',
  '/cover on adds decoy traffic so the relay can’t tell when you’re really chatting.',
  '/panic wipes every on-disk secret and exits — for a lost or seized device.',
  '/backup saves your identity + verified peers as an encrypted file.',
  'Ctrl+K opens the command palette; Ctrl+E the emoji picker; PgUp/PgDn scrolls.',
  'A ✗ next to a name means their key changed since you last saw it — verify before trusting.',
  '/deniable on switches to plausibly-deniable messages (no cryptographic proof you sent them).',
  'No server? Run it in P2P mode — peers find each other on the LAN via mDNS, no relay at all.',
];

// Pick a tip by index (wraps around). Deterministic — the caller decides the
// index (e.g. a random one at startup, or an incrementing one for /tips).
export function tipAt(index, tips = TIPS) {
  if (tips.length === 0) {
    return '';
  }
  const i = ((index % tips.length) + tips.length) % tips.length;
  return tips[i];
}

// One random tip — used at startup. (Runtime only; not used in workflow scripts.)
export function randomTip(tips = TIPS) {
  return tipAt(Math.floor(Math.random() * tips.length), tips);
}
