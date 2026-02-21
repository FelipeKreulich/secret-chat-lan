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
  LIST_ROOMS: 'list_rooms',
  ROOM_LIST: 'room_list',
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
};

// ── Factory helpers ────────────────────────────────────────────
function base(type) {
  return { type, version: PROTOCOL_VERSION, timestamp: Date.now() };
}

export function createJoin(nickname, publicKeyB64) {
  return { ...base(MSG.JOIN), nickname, publicKey: publicKeyB64 };
}

export function createJoinAck(sessionId, peers, queuedCount = 0, room = 'general') {
  const ack = { ...base(MSG.JOIN_ACK), sessionId, peers, room };
  if (queuedCount > 0) {
    ack.queuedCount = queuedCount;
  }
  return ack;
}

export function createPeerJoined(peer) {
  return { ...base(MSG.PEER_JOINED), peer };
}

export function createPeerLeft(sessionId, nickname) {
  return { ...base(MSG.PEER_LEFT), sessionId, nickname };
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
  return {
    ...base(MSG.ENCRYPTED_MESSAGE),
    from,
    to,
    payload: {
      ephemeralPublicKey: payload.ephemeralPublicKey.toString('base64'),
      counter: payload.counter,
      previousCounter: payload.previousCounter,
      ciphertext: payload.ciphertext.toString('base64'),
      nonce: payload.nonce.toString('base64'),
    },
  };
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

export function createChangeRoom(room) {
  return { ...base(MSG.CHANGE_ROOM), room };
}

export function createRoomChanged(room, peers) {
  return { ...base(MSG.ROOM_CHANGED), room, peers };
}

export function createListRooms() {
  return base(MSG.LIST_ROOMS);
}

export function createRoomList(rooms) {
  return { ...base(MSG.ROOM_LIST), rooms };
}
