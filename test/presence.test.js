import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';
import { createServer } from 'node:net';
import { bucketFor, startPresenceServer } from '../src/server/presence.js';

/**
 * Port 0 means "disabled" to startPresenceServer, not "pick one for me", so the
 * test has to find a free port itself.
 */
function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

describe('bucketFor', () => {
  test('maps counts to their bucket', () => {
    assert.equal(bucketFor(0), '0');
    assert.equal(bucketFor(1), '1-5');
    assert.equal(bucketFor(5), '1-5');
    assert.equal(bucketFor(6), '6-20');
    assert.equal(bucketFor(20), '6-20');
    assert.equal(bucketFor(21), '21-50');
    assert.equal(bucketFor(50), '21-50');
    assert.equal(bucketFor(51), '50+');
    assert.equal(bucketFor(9999), '50+');
  });

  test('hides individual arrivals inside a bucket', () => {
    // The whole point: someone polling this endpoint must not be able to watch
    // people come and go. Within a bucket the answer does not move.
    assert.equal(bucketFor(1), bucketFor(4));
    assert.equal(bucketFor(7), bucketFor(19));
  });

  test('survives nonsense input', () => {
    assert.equal(bucketFor(-1), '0');
    assert.equal(bucketFor(NaN), '0');
    assert.equal(bucketFor(undefined), '0');
    assert.equal(bucketFor(2.7), '1-5');
  });
});

describe('presence server', () => {
  let server;
  let url;
  const sessions = { size: 0 };

  before(async () => {
    const port = await freePort();
    server = startPresenceServer(sessions, port);
    await new Promise((resolve) => {
      if (server.listening) return resolve();
      server.once('listening', resolve);
    });
    url = `http://127.0.0.1:${port}`;
  });

  after(() => server?.close());

  test('does not listen at all without a port', () => {
    assert.equal(startPresenceServer(sessions, 0), null);
    assert.equal(startPresenceServer(sessions, undefined), null);
  });

  test('reports the bucket for the current session count', async () => {
    sessions.size = 3;
    const res = await fetch(`${url}/presence`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { online: '1-5' });
  });

  test('never exposes the exact count', async () => {
    sessions.size = 7;
    const body = await (await fetch(`${url}/presence`)).text();
    assert.ok(body.includes('6-20'));
    assert.ok(!body.includes('7'), `exact count leaked: ${body}`);
  });

  test('exposes nothing but the bucket', async () => {
    // Room names, nicknames and addresses are exactly what the relay refuses to
    // hand over. A convenience endpoint must not become the exception.
    sessions.size = 2;
    const payload = await (await fetch(`${url}/presence`)).json();
    assert.deepEqual(Object.keys(payload), ['online']);
  });

  test('404s on anything else', async () => {
    assert.equal((await fetch(`${url}/`)).status, 404);
    assert.equal((await fetch(`${url}/rooms`)).status, 404);
    assert.equal((await fetch(`${url}/presence`, { method: 'POST' })).status, 404);
  });
});
