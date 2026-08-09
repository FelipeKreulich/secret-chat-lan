import { PROTOCOL_VERSION } from '../shared/constants.js';

// ── Message types ──────────────────────────────────────────────
export const MSG = {
  JOIN: 'join',
  JOIN_ACK: 'join_ack',
  PEER_JOINED: 'peer_joined',
  PEER_LEFT: 'peer_left',
  ENCRYPTED_MESSAGE: 'encrypted_message',
  ERROR: 'error',
  KEY_UPDATE: 'key_update',
  PEER_KEY_UPDATED: 'peer_key_updated',
  CHANGE_ROOM: 'change_room',
  ROOM_CHANGED: 'room_changed',
  JOIN_ROOM: 'join_room',
  ROOM_JOINED: 'room_joined',
  LEAVE_ROOM: 'leave_room',
  ROOM_LEFT: 'room_left',
  LIST_ROOMS: 'list_rooms',
  ROOM_LIST: 'room_list',
  ROOM_CHALLENGE: 'room_challenge',
  ROOM_AUTH: 'room_auth',
  KICK_PEER: 'kick_peer',
  MUTE_PEER: 'mute_peer',
  BAN_PEER: 'ban_peer',
  PEER_KICKED: 'peer_kicked',
  PEER_MUTED: 'peer_muted',
  PING: 'ping',
  PONG: 'pong',
};

// ── Error codes ────────────────────────────────────────────────
export const ERR = {
  NICKNAME_TAKEN: 'NICKNAME_TAKEN',
  INVALID_MESSAGE: 'INVALID_MESSAGE',
  PEER_NOT_FOUND: 'PEER_NOT_FOUND',
  RATE_LIMITED: 'RATE_LIMITED',
  PAYLOAD_TOO_LARGE: 'PAYLOAD_TOO_LARGE',
  ROOM_AUTH_FAILED: 'ROOM_AUTH_FAILED',
  ROOM_EXISTS: 'ROOM_EXISTS',
};

// ── Factory helpers ────────────────────────────────────────────
function base(type) {
  return { type, version: PROTOCOL_VERSION, timestamp: Date.now() };
}

// pqPublicKey (v3, optional): ML-KEM-768 encapsulation key for the hybrid
// post-quantum handshake. Absent = classical-only peer (pre-2.3 client).
// caps (optional): what this client can do beyond the baseline protocol. Omitted
// when empty so the wire is byte-identical to a pre-capability client.
export function createJoin(nickname, publicKeyB64, pqPublicKeyB64 = null, caps = null) {
  const msg = { ...base(MSG.JOIN), nickname, publicKey: publicKeyB64 };
  if (pqPublicKeyB64) {
    msg.pqPublicKey = pqPublicKeyB64;
  }
  if (Array.isArray(caps) && caps.length > 0) {
    msg.caps = [...caps];
  }
  return msg;
}

export function createJoinAck(sessionId, peers, queuedCount = 0, room = 'general') {
  const ack = { ...base(MSG.JOIN_ACK), sessionId, peers, room };
  if (queuedCount > 0) {
    ack.queuedCount = queuedCount;
  }
  return ack;
}

// `room` (multi-room, additive): which room this event refers to. A peer can
// leave room X while still sharing room Y with you. Old clients ignore it.
export function createPeerJoined(peer, room = null) {
  const msg = { ...base(MSG.PEER_JOINED), peer };
  if (room) {
    msg.room = room;
  }
  return msg;
}

export function createPeerLeft(sessionId, nickname, room = null) {
  const msg = { ...base(MSG.PEER_LEFT), sessionId, nickname };
  if (room) {
    msg.room = room;
  }
  return msg;
}

export function createEncryptedMessage(from, to, ciphertextB64, nonceB64) {
  return {
    ...base(MSG.ENCRYPTED_MESSAGE),
    from,
    to,
    payload: { ciphertext: ciphertextB64, nonce: nonceB64 },
  };
}

export function createRatchetedMessage(from, to, payload) {
  const inner = {
    ephemeralPublicKey: payload.ephemeralPublicKey.toString('base64'),
    counter: payload.counter,
    previousCounter: payload.previousCounter,
    ciphertext: payload.ciphertext.toString('base64'),
    nonce: payload.nonce.toString('base64'),
  };
  // Hybrid PQ: the KEM ciphertext rides along until the peer has folded it in.
  // It is sealed to the recipient like everything else — the relay sees only
  // an opaque blob.
  if (payload.pqCiphertext) {
    inner.pqCiphertext = payload.pqCiphertext.toString('base64');
  }
  return { ...base(MSG.ENCRYPTED_MESSAGE), from, to, payload: inner };
}

// Sealed-sender envelope (protocol v2): the relay sees only the recipient and an
// opaque blob. The sender's identity + the inner payload are sealed to the
// recipient's key (see crypto/SealedSender.js). There is deliberately no `from`.
export function createSealedMessage(to, sealedB64) {
  return { ...base(MSG.ENCRYPTED_MESSAGE), to, sealed: sealedB64 };
}

export function createError(code, message) {
  return { ...base(MSG.ERROR), code, message };
}

export function createKeyUpdate(publicKeyB64) {
  return { ...base(MSG.KEY_UPDATE), publicKey: publicKeyB64 };
}

export function createPeerKeyUpdated(sessionId, publicKeyB64) {
  return { ...base(MSG.PEER_KEY_UPDATED), sessionId, publicKey: publicKeyB64 };
}

export function createPing() {
  return base(MSG.PING);
}

export function createPong() {
  return base(MSG.PONG);
}

// roomAuthPk (optional): Ed25519 verifier public key — present only when
// CREATING a private room; the server stores it in memory as the room's
// password verifier (see crypto/RoomKey.js).
export function createChangeRoom(room, roomAuthPkB64 = null) {
  const msg = { ...base(MSG.CHANGE_ROOM), room };
  if (roomAuthPkB64) {
    msg.roomAuthPk = roomAuthPkB64;
  }
  return msg;
}

export function createRoomChanged(room, peers, isPrivate = false) {
  const msg = { ...base(MSG.ROOM_CHANGED), room, peers };
  if (isPrivate) {
    msg.private = true;
  }
  return msg;
}

// ── Multi-room (IRC-style buffers) ─────────────────────────────
// join_room ADDS a membership (unlike change_room, which replaces them all).
// Same optional roomAuthPk as change_room for creating a private room.
export function createJoinRoom(room, roomAuthPkB64 = null) {
  const msg = { ...base(MSG.JOIN_ROOM), room };
  if (roomAuthPkB64) {
    msg.roomAuthPk = roomAuthPkB64;
  }
  return msg;
}

export function createRoomJoined(room, peers, isPrivate = false) {
  const msg = { ...base(MSG.ROOM_JOINED), room, peers };
  if (isPrivate) {
    msg.private = true;
  }
  return msg;
}

export function createLeaveRoom(room) {
  return { ...base(MSG.LEAVE_ROOM), room };
}

export function createRoomLeft(room) {
  return { ...base(MSG.ROOM_LEFT), room };
}

// Server → client: the target room is private; prove password knowledge by
// signing this nonce. The password itself never travels.
export function createRoomChallenge(room, nonceB64) {
  return { ...base(MSG.ROOM_CHALLENGE), room, nonce: nonceB64 };
}

// Client → server: Ed25519 signature over (room, nonce, sessionId) with the
// password-derived key (see crypto/RoomKey.js#signRoomChallenge).
export function createRoomAuth(room, nonceB64, signatureB64) {
  return { ...base(MSG.ROOM_AUTH), room, nonce: nonceB64, signature: signatureB64 };
}

export function createListRooms() {
  return base(MSG.LIST_ROOMS);
}

export function createRoomList(rooms) {
  return { ...base(MSG.ROOM_LIST), rooms };
}

export function createKickPeer(targetNickname, reason = '') {
  return { ...base(MSG.KICK_PEER), targetNickname, reason };
}

export function createMutePeer(targetNickname, durationMs) {
  return { ...base(MSG.MUTE_PEER), targetNickname, durationMs };
}

export function createBanPeer(targetNickname, reason = '') {
  return { ...base(MSG.BAN_PEER), targetNickname, reason };
}

export function createPeerKicked(nickname, reason = '') {
  return { ...base(MSG.PEER_KICKED), nickname, reason };
}

export function createPeerMuted(nickname, durationMs) {
  return { ...base(MSG.PEER_MUTED), nickname, durationMs };
}
