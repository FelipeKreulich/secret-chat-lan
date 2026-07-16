import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocketServer } from 'ws';
import { once } from 'node:events';
import { Connection } from '../src/client/Connection.js';

describe('Connection', () => {
  let server;
  let port;
  let conns;

  beforeEach(async () => {
    server = new WebSocketServer({ port: 0 });
    await once(server, 'listening');
    port = server.address().port;
    conns = [];
  });

  afterEach(async () => {
    for (const c of conns) {
      c.close();
    }
    await new Promise((r) => server.close(r));
  });

  const connect = () => {
    const c = new Connection(`ws://localhost:${port}`);
    conns.push(c);
    return c;
  };

  it('emits connected and flips the connected getter on open', async () => {
    const c = connect();
    assert.equal(c.connected, false);
    c.connect();
    await once(c, 'connected');
    assert.equal(c.connected, true);
    assert.equal(c.url, `ws://localhost:${port}`);
  });

  it('send delivers to the server when open and returns false when closed', async () => {
    const received = new Promise((res) => {
      server.on('connection', (ws) => ws.on('message', (d) => res(JSON.parse(d.toString()))));
    });
    const c = connect();
    assert.equal(c.send({ hi: 1 }), false, 'no socket yet → false');
    c.connect();
    await once(c, 'connected');
    assert.equal(c.send({ type: 'ping', n: 7 }), true);
    assert.deepEqual(await received, { type: 'ping', n: 7 });
  });

  it('parses valid JSON into a message event and ignores malformed frames', async () => {
    server.on('connection', (ws) => {
      ws.send('not json {{{'); // must be swallowed, not crash
      ws.send(JSON.stringify({ type: 'hello', ok: true }));
    });
    const c = connect();
    c.connect();
    const [msg] = await once(c, 'message');
    assert.deepEqual(msg, { type: 'hello', ok: true });
  });

  it('emits disconnected then reconnecting after the socket drops', async () => {
    let n = 0;
    server.on('connection', (ws) => {
      n++;
      if (n === 1) {
        ws.close(); // drop the first connection
      }
    });
    const c = connect();
    c.connect();
    await once(c, 'disconnected');
    const [delay] = await once(c, 'reconnecting');
    assert.ok(delay >= 1000, 'reconnect uses the base backoff');
  });

  it('close() stops any further reconnection', async () => {
    const c = connect();
    c.connect();
    await once(c, 'connected');
    let reconnected = false;
    c.on('reconnecting', () => {
      reconnected = true;
    });
    c.close();
    await new Promise((r) => setTimeout(r, 1300));
    assert.equal(reconnected, false);
    assert.equal(c.connected, false);
  });
});
