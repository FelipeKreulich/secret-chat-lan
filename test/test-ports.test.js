import { strict as assert } from 'node:assert';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

/**
 * No two test files may listen on the same port.
 *
 * The runner executes files in parallel, so a shared port is not the clash you
 * would expect. One server binds, the other fails quietly, and its clients
 * connect to the *first* file's relay — where their sessions do not exist, so
 * they wait for replies that will never come and the failure surfaces minutes
 * later as a timeout in whichever file lost the race.
 *
 * That cost an afternoon: the symptom was two multi-room tests failing, and the
 * cause was a new file three directories away picking a port that was taken.
 * The ports are hand-assigned, so this is the only thing standing between the
 * next person and the same afternoon.
 */
test('every test file listens on its own port', () => {
  const used = new Map(); // port -> file

  for (const file of readdirSync(here).filter((f) => f.endsWith('.test.js'))) {
    const source = readFileSync(join(here, file), 'utf8');
    for (const [, port] of source.matchAll(/(?:TEST_PORT|PORT)\s*=\s*(\d{4,5})\b/g)) {
      const owner = used.get(port);
      assert.equal(
        owner,
        undefined,
        `${file} listens on ${port}, which ${owner} already uses. ` +
          'Pick another: files run in parallel and clients would reach the wrong relay.',
      );
      used.set(port, file);
    }
  }

  // If this ever finds nothing, the regex stopped matching how ports are
  // declared and the check has quietly become decorative.
  assert.ok(used.size >= 3, `expected several ports, found ${used.size}`);
});
