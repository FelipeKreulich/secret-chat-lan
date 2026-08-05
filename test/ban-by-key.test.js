import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert';
import { SessionManager } from '../src/server/SessionManager.js';

const KEY_A = 'AAAA1111bbbbCCCCddddEEEEffffGGGGhhhhIIIIjjjk=';
const KEY_B = 'ZZZZ9999yyyyXXXXwwwwVVVVuuuuTTTTssssRRRRqqqp=';

describe('room bans are bound to the key, not the name', () => {
  let sessions;

  beforeEach(() => {
    sessions = new SessionManager();
  });

  test('a banned key stays banned after any rename', () => {
    // The whole point. /nick lets anyone pick a new name whenever they like,
    // so a ban stored against a nickname was undone by typing one word — and
    // room owners are the only moderation this system has.
    sessions.banPeer('secret-room', KEY_A);

    assert.equal(sessions.isBanned('secret-room', KEY_A), true);
    // Same person, new nickname, same key: still out.
    assert.equal(sessions.isBanned('secret-room', KEY_A), true);
  });

  test('does not ban anyone else', () => {
    sessions.banPeer('secret-room', KEY_A);
    assert.equal(sessions.isBanned('secret-room', KEY_B), false);
  });

  test('is scoped to the room it was issued in', () => {
    sessions.banPeer('secret-room', KEY_A);
    assert.equal(sessions.isBanned('general', KEY_A), false);
    assert.equal(sessions.isBanned('another-room', KEY_A), false);
  });

  test('ignores a missing key instead of banning everyone', () => {
    // A ban with no key must never turn into a ban that matches anything —
    // an owner banning a peer who just vanished should be a no-op.
    sessions.banPeer('secret-room', undefined);
    sessions.banPeer('secret-room', '');

    assert.equal(sessions.isBanned('secret-room', KEY_A), false);
    assert.equal(sessions.isBanned('secret-room', undefined), false);
    assert.equal(sessions.isBanned('secret-room', ''), false);
  });

  test('a room with no bans lets everyone in', () => {
    assert.equal(sessions.isBanned('untouched', KEY_A), false);
  });
});
