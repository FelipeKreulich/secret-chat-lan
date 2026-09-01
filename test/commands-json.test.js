import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const commands = JSON.parse(readFileSync(join(root, 'docs/commands.json'), 'utf8'));
const all = commands.groups.flatMap((group) => group.commands);

test('docs/commands.json is up to date with the code', () => {
  // The counts drifted twice before this file existed — the README's table was
  // short of the truth, and the website advertised 66 and 63 when the real
  // numbers were 67 and 64. Adding a command and forgetting to regenerate
  // should fail here rather than quietly ship a wrong list to the website.
  assert.doesNotThrow(
    () =>
      execFileSync('node', ['scripts/generate-commands.mjs', '--check'], {
        cwd: root,
        stdio: 'pipe',
      }),
    'run: npm run commands:build',
  );
});

test('every command is documented', () => {
  const undocumented = all.filter((command) => !command.summary);
  assert.deepEqual(
    undocumented.map((command) => command.name),
    [],
    'these commands exist in a controller but appear in neither the README nor the Ctrl+K palette',
  );
});

test('every command works somewhere', () => {
  // A command with no modes would mean the generator matched a `case` label
  // that is not in either controller — a parsing bug, not a real command.
  assert.deepEqual(
    all.filter((command) => command.modes.length === 0),
    [],
  );
});

test('P2P is a subset of the relay client', () => {
  // Not a rule of the universe, but it is the promise the website makes: every
  // P2P command is also a relay command, and only a handful are relay-only. If
  // that ever stops being true the site's wording has to change with it.
  const relayOnly = all
    .filter((command) => !command.modes.includes('p2p'))
    .map((command) => command.name)
    .sort();

  assert.deepEqual(
    all.filter((command) => !command.modes.includes('relay')),
    [],
    'a P2P-only command would break how the commands page is filtered',
  );
  // /device joined them in 2.13.0. Multi-device in the mesh is a different
  // design — P2PChatController keys peers by nickname and has no sessions — and
  // is deliberately out of scope; docs/design/multi-device.md says so.
  // /panel joined them in the room-panes work: P2P has /join but never opens a
  // second buffer — P2PChatController holds one #currentRoom and calls neither
  // toBuffer nor switchBuffer — so a panel there would be one column of one
  // room, which is what it already is.
  assert.deepEqual(relayOnly, ['/create', '/device', '/invite', '/nick', '/panel']);
});

test('the counts match the list', () => {
  assert.equal(commands.counts.total, all.length);
  assert.equal(
    commands.counts.relay,
    all.filter((command) => command.modes.includes('relay')).length,
  );
  assert.equal(commands.counts.p2p, all.filter((command) => command.modes.includes('p2p')).length);
});
