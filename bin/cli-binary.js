// Entry point for the standalone CipherMesh binary (`bun build --compile`).
//
// Separate from bin/ciphermesh.js because that one dispatches through
// `await import(new URL(target, import.meta.url))` — a computed specifier no
// bundler can follow, which is why the binary used to contain nothing but the
// launcher. Here the three specifiers are literal, so the bundler pulls in all
// three modes and the branch picks one at runtime.
//
// The version is injected at build time: reading package.json off disk does not
// work once everything lives inside the binary.
const VERSION = process.env.CIPHERMESH_VERSION || 'unknown';

const HELP = `CipherMesh — end-to-end encrypted terminal chat

Usage:
  ciphermesh [client]   connect to a relay server (default)
  ciphermesh server     run the zero-knowledge relay server
  ciphermesh p2p        serverless mode (mDNS peer discovery on the LAN)

Options:
  -h, --help            show this help
  -v, --version         show the version

Client options:
  --setup               re-run the first-run setup wizard
  --no-onboard          skip the first-run wizard (scripts/CI)
  --fresh               forget the last session (server/room) and start clean
`;

const arg = process.argv[2];

if (arg === '-h' || arg === '--help' || arg === 'help') {
  process.stdout.write(HELP);
} else if (arg === '-v' || arg === '--version') {
  process.stdout.write(`${VERSION}\n`);
} else if (arg === 'server') {
  await import('../src/server/index.js');
} else if (arg === 'p2p') {
  await import('../src/p2p/index.js');
} else {
  await import('../src/client/index.js');
}
