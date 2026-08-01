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

describe('SessionManager — private rooms', () => {
  it('stores and reports the room verifier', () => {
    const sm = new SessionManager();
    sm.addSession(fakeWs(), 'alice', 'pkA', 'cofre');
    sm.setRoomPrivate('cofre', 'verifier-b64');

    assert.equal(sm.isRoomPrivate('cofre'), true);
    assert.equal(sm.getRoomAuthPk('cofre'), 'verifier-b64');
    assert.equal(sm.isRoomPrivate('general'), false);
    assert.equal(sm.getRoomAuthPk('general'), null);
  });

  it('drops the verifier when the room empties — the room dies with its password', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'cofre');
    sm.setRoomPrivate('cofre', 'verifier-b64');

    sm.removeSession(a); // room empties

    assert.equal(sm.isRoomPrivate('cofre'), false);
    assert.equal(sm.getRoomAuthPk('cofre'), null);
  });

  it('keeps the verifier while members remain', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'cofre');
    sm.addSession(fakeWs(), 'bob', 'pkB', 'cofre');
    sm.setRoomPrivate('cofre', 'verifier-b64');

    sm.removeSession(a);

    assert.equal(sm.isRoomPrivate('cofre'), true);
  });

  it('listRooms marks private rooms', () => {
    const sm = new SessionManager();
    sm.addSession(fakeWs(), 'alice', 'pkA', 'cofre');
    sm.addSession(fakeWs(), 'bob', 'pkB', 'aberta');
    sm.setRoomPrivate('cofre', 'verifier-b64');

    const rooms = sm.listRooms();
    assert.equal(rooms.find((r) => r.name === 'cofre').private, true);
    assert.equal(rooms.find((r) => r.name === 'aberta').private, false);
    assert.equal(rooms.find((r) => r.name === 'general').private, false);
  });

  it('multi-room: joinAdditional keeps existing memberships', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'general');

    assert.deepEqual(sm.getSessionRooms(a), ['general']);
    assert.ok(sm.joinAdditional(a, 'dev'));
    assert.deepEqual(sm.getSessionRooms(a).sort(), ['dev', 'general']);
    assert.equal(sm.isInRoom(a, 'dev'), true);
    assert.equal(sm.joinAdditional(a, 'dev'), null, 'joining twice is refused');
    assert.equal(sm.isRoomOwner('dev', a), true, 'creator of the extra room owns it');
  });

  it('multi-room: leaveOneRoom refuses the last room', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'general');
    sm.joinAdditional(a, 'dev');

    assert.deepEqual(sm.leaveOneRoom(a, 'dev'), { room: 'dev' });
    assert.deepEqual(sm.getSessionRooms(a), ['general']);
    assert.deepEqual(sm.leaveOneRoom(a, 'general'), { lastRoom: true }, 'last room is refused');
    assert.equal(sm.leaveOneRoom(a, 'nunca'), null, 'not a member');
  });

  it('multi-room: peers are room-scoped; switchRoom leaves every room', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'general');
    const b = sm.addSession(fakeWs(), 'bob', 'pkB', 'general');
    sm.joinAdditional(a, 'dev');

    assert.equal(sm.getPeers(b, 'general').length, 1, 'bob sees alice in general');
    assert.equal(sm.getPeers(a, 'dev').length, 0, 'alice alone in dev');

    const result = sm.switchRoom(a, 'outra');
    assert.deepEqual(result.oldRooms.sort(), ['dev', 'general'], 'switch leaves all rooms');
    assert.deepEqual(sm.getSessionRooms(a), ['outra']);
    assert.equal(sm.getPeers(b, 'general').length, 0);
  });

  it('multi-room: getSessionRoom is null when in several rooms (legacy helper)', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'general');
    assert.equal(sm.getSessionRoom(a), 'general');
    sm.joinAdditional(a, 'dev');
    assert.equal(sm.getSessionRoom(a), null);
  });

  it('multi-room: broadcastToPeersOf dedupes peers sharing several rooms', () => {
    const sm = new SessionManager();
    const wsB = {
      readyState: 1,
      sent: [],
      send(m) {
        this.sent.push(m);
      },
    };
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'general');
    const b = sm.addSession(wsB, 'bob', 'pkB', 'general');
    sm.joinAdditional(a, 'dev');
    sm.joinAdditional(b, 'dev');

    sm.broadcastToPeersOf(a, { type: 'x' });
    assert.equal(wsB.sent.length, 1, 'bob shares two rooms but gets exactly one copy');
  });

  it('multi-room: removeSession cleans up every room', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'sala1');
    sm.joinAdditional(a, 'sala2');
    sm.removeSession(a);

    const rooms = sm.listRooms().map((r) => r.name);
    assert.ok(!rooms.includes('sala1') && !rooms.includes('sala2'), 'both rooms died');
  });

  it('roomHasMembers distinguishes occupied, empty and unknown rooms', () => {
    const sm = new SessionManager();
    const a = sm.addSession(fakeWs(), 'alice', 'pkA', 'cofre');
    assert.equal(sm.roomHasMembers('cofre'), true);
    assert.equal(sm.roomHasMembers('nunca-existiu'), false);

    sm.removeSession(a);
    assert.equal(sm.roomHasMembers('cofre'), false);
  });
});
