import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SessionManager } from '../src/server/SessionManager.js';

function fakeWs() {
  return { readyState: 1, send() {} };
}

describe('SessionManager — room ownership & cleanup', () => {
  it('assigns ownership to the creator of a non-general room', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'sala1');
    assert.equal(sm.isRoomOwner('sala1', a), true);
  });

  it('does not assign an owner to the general room', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'general');
    assert.equal(sm.getRoomOwner('general'), null);
    assert.equal(sm.isRoomOwner('general', a), false);
  });

  it('transfers ownership when the owner leaves but members remain', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'sala1');
    const b = sm.addSession(fakeWs(), 'bob', 'pkB', 'sala1');
    assert.equal(sm.isRoomOwner('sala1', a), true);

    sm.removeSession(a);

    assert.equal(sm.getRoomOwner('sala1'), b, 'ownership must pass to a remaining member');
    assert.equal(sm.isRoomOwner('sala1', b), true);
  });

  it('clears ownership when a non-general room empties, so a recreated room gets a fresh owner', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'sala1');
    sm.removeSession(a); // room now empty

    assert.equal(sm.getRoomOwner('sala1'), null);

    // Recreate the same room with a different user — must NOT stay owner-less
    const c = sm.addSession(fakeWs(), 'carol', 'pkC', 'sala1');
    assert.equal(sm.isRoomOwner('sala1', c), true, 'recreated room must have a fresh owner');
  });

  it('drops the per-room ban list when the room empties', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'sala1');
    sm.banPeer('sala1', 'mallory');
    assert.equal(sm.isBanned('sala1', 'mallory'), true);

    sm.removeSession(a); // room empties → ban list cleared

    assert.equal(sm.isBanned('sala1', 'mallory'), false);
  });

  it('switchRoom transfers ownership of the old room to a remaining member', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'sala1'); // owner of sala1
    const b = sm.addSession(fakeWs(), 'bob', 'pkB', 'sala1');

    sm.switchRoom(a, 'sala2'); // alice leaves sala1, creates sala2

    assert.equal(sm.getRoomOwner('sala1'), b, 'sala1 must pass to bob');
    assert.equal(sm.isRoomOwner('sala2', a), true, 'alice owns the room she created');
  });
});
