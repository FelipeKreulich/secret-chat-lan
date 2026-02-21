import {
  PROTOCOL_VERSION,
  MAX_NICKNAME_LENGTH,
  MAX_PAYLOAD_SIZE,
  PUBLIC_KEY_SIZE,
} from '../shared/constants.js';

// ── Helpers ────────────────────────────────────────────────────
function isString(v) {
  return typeof v === 'string';
}

function isNumber(v) {
  return typeof v === 'number' && Number.isFinite(v);
}

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function isValidBase64(str, expectedBytes) {
  if (!isString(str)) {
    return false;
  }
  try {
    const buf = Buffer.from(str, 'base64');
    return expectedBytes ? buf.length === expectedBytes : buf.length > 0;
  } catch {
    return false;
  }
}

function sanitizeNickname(nick) {
  if (!isString(nick)) {
    return null;
  }
  // eslint-disable-next-line no-control-regex
  const clean = nick.replace(/[\x00-\x1f\x7f]/g, '').trim();
  if (clean.length === 0 || clean.length > MAX_NICKNAME_LENGTH) {
    return null;
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(clean)) {
    return null;
  }
  return clean;
}

// ── Parse + validate incoming JSON ─────────────────────────────
export function parseMessage(raw) {
  if (typeof raw === 'string' && raw.length > MAX_PAYLOAD_SIZE) {
    return { valid: false, error: 'Payload too large' };
  }

  let msg;
  try {
    msg = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch {
    return { valid: false, error: 'Invalid JSON' };
  }

  if (!isObject(msg)) {
    return { valid: false, error: 'Message must be an object' };
  }
  if (msg.version !== PROTOCOL_VERSION) {
    return { valid: false, error: `Unsupported protocol version: ${msg.version}` };
  }
  if (!isString(msg.type)) {
    return { valid: false, error: 'Missing message type' };
  }
  if (!isNumber(msg.timestamp)) {
    return { valid: false, error: 'Missing timestamp' };
  }

  return { valid: true, msg };
}

// ── Type-specific validators ───────────────────────────────────
export function validateJoin(msg) {
  const nick = sanitizeNickname(msg.nickname);
  if (!nick) {
    return { valid: false, error: 'Invalid nickname (1-20 chars, alphanumeric/underscore/dash)' };
  }
  if (!isValidBase64(msg.publicKey, PUBLIC_KEY_SIZE)) {
    return { valid: false, error: 'Invalid public key' };
  }
  return { valid: true, nickname: nick };
}

export function validateEncryptedMessage(msg) {
  if (!isString(msg.from) || !isString(msg.to)) {
    return { valid: false, error: 'Missing from/to fields' };
  }
  if (!isObject(msg.payload)) {
    return { valid: false, error: 'Missing payload' };
  }
  if (!isString(msg.payload.ciphertext) || !isString(msg.payload.nonce)) {
    return { valid: false, error: 'Invalid payload structure' };
  }
  if (!isValidBase64(msg.payload.nonce, 24)) {
    return { valid: false, error: 'Invalid nonce' };
  }

  // Ratcheted message: validate extra fields
  if (msg.payload.ephemeralPublicKey !== undefined) {
    if (!isValidBase64(msg.payload.ephemeralPublicKey, PUBLIC_KEY_SIZE)) {
      return { valid: false, error: 'Invalid ephemeral public key' };
    }
    if (!Number.isInteger(msg.payload.counter) || msg.payload.counter < 0) {
      return { valid: false, error: 'Invalid counter' };
    }
    if (!Number.isInteger(msg.payload.previousCounter) || msg.payload.previousCounter < 0) {
      return { valid: false, error: 'Invalid previousCounter' };
    }
  }

  return { valid: true };
}

export function validateKeyUpdate(msg) {
  if (!isValidBase64(msg.publicKey, PUBLIC_KEY_SIZE)) {
    return { valid: false, error: 'Invalid public key' };
  }
  return { valid: true };
}

export function validateChangeRoom(msg) {
  if (!isString(msg.room) || msg.room.length === 0 || msg.room.length > 30) {
    return { valid: false, error: 'Invalid room name (1-30 chars)' };
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(msg.room)) {
    return { valid: false, error: 'Room name must be alphanumeric, dash or underscore' };
  }
  return { valid: true, room: msg.room.toLowerCase() };
}

export function validateListRooms() {
  return { valid: true };
}

export function validateKickPeer(msg) {
  const nick = sanitizeNickname(msg.targetNickname);
  if (!nick) {
    return { valid: false, error: 'Invalid target nickname' };
  }
  return { valid: true, targetNickname: nick, reason: isString(msg.reason) ? msg.reason.slice(0, 200) : '' };
}

export function validateMutePeer(msg) {
  const nick = sanitizeNickname(msg.targetNickname);
  if (!nick) {
    return { valid: false, error: 'Invalid target nickname' };
  }
  if (!isNumber(msg.durationMs) || msg.durationMs <= 0) {
    return { valid: false, error: 'Invalid mute duration' };
  }
  return { valid: true, targetNickname: nick, durationMs: msg.durationMs };
}

export function validateBanPeer(msg) {
  const nick = sanitizeNickname(msg.targetNickname);
  if (!nick) {
    return { valid: false, error: 'Invalid target nickname' };
  }
  return { valid: true, targetNickname: nick, reason: isString(msg.reason) ? msg.reason.slice(0, 200) : '' };
}

export { sanitizeNickname };
