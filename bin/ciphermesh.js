#!/usr/bin/env node
// CipherMesh CLI entry point — dispatches to the client (default), the relay
// server, or serverless P2P mode. Enables `npx ciphermesh` after publishing.
import { readFileSync } from 'node:fs';

const TARGETS = {
  client: '../src/client/index.js',
  server: '../src/server/index.js',
  p2p: '../src/p2p/index.js',
};

const HELP = `CipherMesh — end-to-end encrypted terminal chat

Usage:
  ciphermesh [client]   connect to a relay server (default)
  ciphermesh server     run the zero-knowledge relay server
  ciphermesh p2p        serverless mode (mDNS peer discovery on the LAN)

Options:
  -h, --help            show this help
  -v, --version         show the version
`;

const arg = process.argv[2];

if (arg === '-h' || arg === '--help' || arg === 'help') {
  process.stdout.write(HELP);
} else if (arg === '-v' || arg === '--version') {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf-8'));
  process.stdout.write(`${pkg.version}\n`);
} else {
  const target = TARGETS[arg] || TARGETS.client;
  await import(new URL(target, import.meta.url).href);
}
