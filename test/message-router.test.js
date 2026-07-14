import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SessionManager } from '../src/server/SessionManager.js';
import { OfflineQueue } from '../src/server/OfflineQueue.js';
import { MessageRouter } from '../src/server/MessageRouter.js';
import { ERR } from '../src/protocol/messages.js';
import { RATE_LIMIT_PER_SECOND } from '../src/shared/constants.js';

function fakeWs() {
  return {
    readyState: 1,
    sent: [],
    send(d) {
      this.sent.push(JSON.parse(d));
    },
  };
}

function setup() {
  const sm = new SessionManager();
  const oq = new OfflineQueue();
  return { sm, oq, router: new MessageRouter(sm, oq) };
}

describe('MessageRouter', () => {
  it('routes a message verbatim to an online recipient', () => {
    const { sm, router } = setup();
    const recWs = fakeWs();
    const s = sm.addSession(fakeWs(), 'alice', 'pkA');
    const r = sm.addSession(recWs, 'bob', 'pkB');

    const msg = { type: 'encrypted_message', to: r, from: s, payload: { secret: 1 } };
    router.route(s, msg);

    assert.equal(recWs.sent.length, 1);
    assert.deepEqual(recWs.sent[0], msg);
  });

  it('sends PEER_NOT_FOUND when the recipient is unknown', () => {
    const { sm, router } = setup();
    const senderWs = fakeWs();
    const s = sm.addSession(senderWs, 'alice', 'pkA');

    router.route(s, { to: 'ghost', from: s, payload: {} });
    assert.equal(senderWs.sent[0].code, ERR.PEER_NOT_FOUND);
  });

  it('enqueues for a recently-left peer instead of erroring', () => {
    const { sm, oq, router } = setup();
    const s = sm.addSession(fakeWs(), 'alice', 'pkA');
    const r = sm.addSession(fakeWs(), 'bob', 'pkB');
    sm.removeSession(r); // bob is now "recently left"

    router.route(s, { to: r, from: s, payload: { x: 1 } });

    assert.equal(oq.size, 1);
    assert.equal(oq.dequeue('bob', 'pkB').length, 1);
  });

  it('rate-limits the sender after the per-second budget', () => {
    const { sm, router } = setup();
    const senderWs = fakeWs();
    const recWs = fakeWs();
    const s = sm.addSession(senderWs, 'alice', 'pkA');
    const r = sm.addSession(recWs, 'bob', 'pkB');
    const msg = { to: r, from: s, payload: {} };

    for (let i = 0; i < RATE_LIMIT_PER_SECOND; i++) {
      router.route(s, msg);
    }
    assert.equal(recWs.sent.length, RATE_LIMIT_PER_SECOND);

    router.route(s, msg); // one over the limit
    assert.equal(recWs.sent.length, RATE_LIMIT_PER_SECOND, 'over-limit message is dropped');
    assert.equal(senderWs.sent.at(-1).code, ERR.RATE_LIMITED);
  });
});
