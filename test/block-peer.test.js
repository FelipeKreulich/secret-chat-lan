import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TrustStore } from '../src/crypto/TrustStore.js';

const KEY_A = Buffer.from('a'.repeat(32)).toString('base64');
const KEY_B = Buffer.from('b'.repeat(32)).toString('base64');

describe('blocking is local, and bound to the key', () => {
  let dir;
  let trust;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'cm-block-'));
    trust = new TrustStore(dir);
    trust.recordPeer('spammer', KEY_A);
    trust.recordPeer('friend', KEY_B);
  });

  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test('blocks the key, so a rename does not undo it', () => {
    // The lesson the ban list had to learn: a nickname is not an identity.
    trust.blockPeer('spammer');
    assert.equal(trust.isBlocked(KEY_A), true);
  });

  test('blocks nobody else', () => {
    trust.blockPeer('spammer');
    assert.equal(trust.isBlocked(KEY_B), false);
  });

  test('cannot block someone never seen', () => {
    assert.equal(trust.blockPeer('nobody'), false);
    assert.equal(trust.isBlocked('some-unknown-key'), false);
  });

  test('unblocks, and says whether there was anything to undo', () => {
    trust.blockPeer('spammer');
    assert.equal(trust.unblockPeer('spammer'), true);
    assert.equal(trust.isBlocked(KEY_A), false);
    assert.equal(trust.unblockPeer('spammer'), false);
  });

  test('survives a restart', () => {
    trust.blockPeer('spammer');
    const reopened = new TrustStore(dir);
    assert.equal(reopened.isBlocked(KEY_A), true);
  });

  test('lists who is blocked, and only them', () => {
    trust.blockPeer('spammer');
    const blocked = trust.listBlocked();
    assert.equal(blocked.length, 1);
    assert.equal(blocked[0].nickname, 'spammer');
  });

  test('an empty key never matches', () => {
    // A blocked record plus a missing key must not silence everyone.
    trust.blockPeer('spammer');
    assert.equal(trust.isBlocked(''), false);
    assert.equal(trust.isBlocked(undefined), false);
    assert.equal(trust.isBlocked(null), false);
  });

  test('panic takes the blocklist with everything else', () => {
    trust.blockPeer('spammer');
    trust.wipe();
    assert.equal(trust.isBlocked(KEY_A), false);
  });
});
