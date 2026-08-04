// Makes sodium-native's addon embeddable, so the binaries actually run on a
// machine that is not the one that built them.
//
// sodium-native resolves its prebuilt `.node` at runtime:
//
//   require.addon = require('require-addon')
//   module.exports = require.addon('.', __filename)
//
// `require-addon` walks the filesystem and sniffs the platform. bun cannot
// follow that, so it does not embed the addon — it leaves an absolute path back
// to the build tree. The binary then works on the build machine and nowhere
// else, which is how this shipped broken since 2.3.0 without anyone noticing
// (issue #427).
//
// Pointing at the exact prebuild makes it a plain static require, which bun
// does embed.
//
// Usage: node scripts/patch-sodium.mjs <platform-arch>
//   e.g. node scripts/patch-sodium.mjs darwin-arm64
//
// The argument is the TARGET, not the host: a cross-compiled build needs the
// target's prebuild, or it embeds an addon the machine cannot load.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

const BINDING = 'node_modules/sodium-native/binding.js';
const MARKER = 'prebuilds/';

const target = process.argv[2];

if (!target) {
  process.stderr.write('Usage: node scripts/patch-sodium.mjs <platform-arch>\n');
  process.exit(1);
}

const prebuild = `node_modules/sodium-native/prebuilds/${target}/sodium-native.node`;

if (!existsSync(prebuild)) {
  // Silently embedding the wrong addon, or none, is exactly the failure this
  // script exists to prevent.
  process.stderr.write(`No prebuild for "${target}" at ${prebuild}\n`);
  process.exit(1);
}

const source = readFileSync(BINDING, 'utf-8');

if (source.includes(MARKER)) {
  process.stdout.write('sodium-native already patched\n');
  process.exit(0);
}

if (!source.includes('require-addon')) {
  // sodium-native changed shape. Failing loudly beats shipping a binary that
  // dies on startup for everyone except us.
  process.stderr.write(`Unexpected contents in ${BINDING}; refusing to patch\n`);
  process.exit(1);
}

writeFileSync(BINDING, `module.exports = require('./prebuilds/${target}/sodium-native.node')\n`);
process.stdout.write(`sodium-native pinned to prebuilds/${target}\n`);
