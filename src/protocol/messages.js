import { PROTOCOL_VERSION } from '../shared/constants.js';

// ── Message types ──────────────────────────────────────────────
export const MSG = {
  JOIN: 'join',
  JOIN_ACK: 'join_ack',
  PEER_JOINED: 'peer_joined',
  PEER_LEFT: 'peer_left',
  ENCRYPTED_MESSAGE: 'encrypted_message',
  ERROR: 'error',
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

export function createJoinAck(sessionId, peers, queuedCount = 0) {
  const ack = { ...base(MSG.JOIN_ACK), sessionId, peers };
  if (queuedCount > 0) ack.queuedCount = queuedCount;
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

export function createError(code, message) {
  return { ...base(MSG.ERROR), code, message };
}

export function createPing() {
  return base(MSG.PING);
}

export function createPong() {
  return base(MSG.PONG);
}
