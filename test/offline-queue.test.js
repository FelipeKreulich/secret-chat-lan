import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { OfflineQueue } from '../src/server/OfflineQueue.js';
import {
  OFFLINE_QUEUE_MAX_PER_PEER,
  OFFLINE_QUEUE_MAX_TOTAL,
} from '../src/shared/constants.js';

describe('OfflineQueue', () => {
  it('enqueues and dequeues in order for a matching publicKey (case-insensitive nick)', () => {
    const q = new OfflineQueue();
    q.enqueue('Bob', 'pkB', { n: 1 });
    q.enqueue('bob', 'pkB', { n: 2 });
    assert.equal(q.size, 2);

    const msgs = q.dequeue('BOB', 'pkB');
    assert.deepEqual(msgs, [{ n: 1 }, { n: 2 }]);
    assert.equal(q.size, 0);
  });

  it('drops the old queue when the publicKey changes on enqueue', () => {
    const q = new OfflineQueue();
    q.enqueue('bob', 'pk1', { n: 1 });
    q.enqueue('bob', 'pk2', { n: 2 });
    assert.equal(q.size, 1);
    assert.deepEqual(q.dequeue('bob', 'pk2'), [{ n: 2 }]);
  });

  it('returns empty and clears when dequeuing with a different publicKey', () => {
    const q = new OfflineQueue();
    q.enqueue('bob', 'pk1', { n: 1 });
    assert.deepEqual(q.dequeue('bob', 'pkX'), []);
    assert.equal(q.size, 0);
  });

  it('returns empty for an unknown peer', () => {
    const q = new OfflineQueue();
    assert.deepEqual(q.dequeue('nobody', 'pk'), []);
  });

  it('caps the per-peer queue, dropping the oldest messages', () => {
    const q = new OfflineQueue();
    for (let i = 0; i < OFFLINE_QUEUE_MAX_PER_PEER + 5; i++) {
      q.enqueue('bob', 'pk', { n: i });
    }
    assert.equal(q.size, OFFLINE_QUEUE_MAX_PER_PEER);

    const msgs = q.dequeue('bob', 'pk');
    assert.equal(msgs.length, OFFLINE_QUEUE_MAX_PER_PEER);
    assert.equal(msgs[0].n, 5, 'oldest 5 were dropped');
  });

  it('enforces the global total cap', () => {
    const q = new OfflineQueue();
    let accepted = 0;
    for (let p = 0; p < 20; p++) {
      for (let i = 0; i < OFFLINE_QUEUE_MAX_PER_PEER; i++) {
        if (q.enqueue(`peer${p}`, 'pk', { p, i })) accepted++;
      }
    }
    assert.equal(accepted, OFFLINE_QUEUE_MAX_TOTAL);
    assert.equal(q.size, OFFLINE_QUEUE_MAX_TOTAL);
    assert.equal(q.enqueue('another', 'pk', {}), false);
  });
});
