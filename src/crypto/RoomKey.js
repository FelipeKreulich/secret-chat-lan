import sodium from 'sodium-native';

// Domain-separation contexts — never reuse across protocols.
const ROOM_SALT_CONTEXT = 'ciphermesh/room-v1:';
const ROOM_AUTH_CONTEXT = 'ciphermesh/room-auth-v1';

/**
 * Derive the secrets of a password-protected room.
 *
 * Argon2id(password, salt=BLAKE2b(context + roomName)) → 64 bytes, split into:
 *  - authSeed (32B) → deterministic Ed25519 keypair. The PUBLIC key is the
 *    verifier the server stores (in memory only); the secret key signs join
 *    challenges. The server never sees the password — and cracking the
 *    verifier costs a full Argon2id derivation per guess.
 *  - roomKey (32B) → symmetric content key layered UNDER the pairwise E2EE,
 *    so even a malicious relay that skips verification and injects a member
 *    cannot read the room without the password.
 *
 * Everyone with (roomName, password) derives the same secrets — nothing else
 * needs to be exchanged.
 *
 * @param {string} roomName - Normalized (lowercase) room name
 * @param {string} password
 * @returns {{ authPublicKey: Buffer, authSecretKey: Buffer, roomKey: Buffer }}
 */
export function deriveRoomSecrets(roomName, password) {
  const salt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES);
  sodium.crypto_generichash(salt, Buffer.from(ROOM_SALT_CONTEXT + roomName, 'utf-8'));

  const seed = sodium.sodium_malloc(
    sodium.crypto_sign_SEEDBYTES + sodium.crypto_secretbox_KEYBYTES,
  );
  sodium.crypto_pwhash(
    seed,
    Buffer.from(password, 'utf-8'),
    salt,
    sodium.crypto_pwhash_OPSLIMIT_MODERATE,
    sodium.crypto_pwhash_MEMLIMIT_MODERATE,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );

  const authSeed = sodium.sodium_malloc(sodium.crypto_sign_SEEDBYTES);
  seed.copy(authSeed, 0, 0, sodium.crypto_sign_SEEDBYTES);
  const roomKey = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES);
  seed.copy(roomKey, 0, sodium.crypto_sign_SEEDBYTES);
  sodium.sodium_memzero(seed);

  const authPublicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
  const authSecretKey = sodium.sodium_malloc(sodium.crypto_sign_SECRETKEYBYTES);
  sodium.crypto_sign_seed_keypair(authPublicKey, authSecretKey, authSeed);
  sodium.sodium_memzero(authSeed);

  return { authPublicKey, authSecretKey, roomKey };
}

/**
 * The exact bytes signed in the join challenge. Binds room + server nonce +
 * the joiner's sessionId, so a captured signature can't be replayed for
 * another session, room or challenge.
 */
function challengeMessage(room, nonceB64, sessionId) {
  return Buffer.from(`${ROOM_AUTH_CONTEXT}:${room}:${nonceB64}:${sessionId}`, 'utf-8');
}

export function signRoomChallenge(authSecretKey, room, nonceB64, sessionId) {
  const signature = Buffer.alloc(sodium.crypto_sign_BYTES);
  sodium.crypto_sign_detached(
    signature,
    challengeMessage(room, nonceB64, sessionId),
    authSecretKey,
  );
  return signature;
}

export function verifyRoomChallenge(authPublicKey, signature, room, nonceB64, sessionId) {
  if (
    !Buffer.isBuffer(authPublicKey) ||
    authPublicKey.length !== sodium.crypto_sign_PUBLICKEYBYTES ||
    !Buffer.isBuffer(signature) ||
    signature.length !== sodium.crypto_sign_BYTES
  ) {
    return false;
  }
  try {
    return sodium.crypto_sign_verify_detached(
      signature,
      challengeMessage(room, nonceB64, sessionId),
      authPublicKey,
    );
  } catch {
    return false;
  }
}

// ── Room content layer ───────────────────────────────────────────
// Applied to the payload BEFORE the pairwise encryption (ratchet/sealed
// sender), which already pads the result — so no extra padding here.

/**
 * Wrap a payload string in the private-room symmetric layer.
 * @returns {string} JSON `{ rk: 1, n, c }` to feed the pairwise encryption
 */
export function encryptRoomPayload(payloadStr, roomKey) {
  const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES);
  sodium.randombytes_buf(nonce);
  const plaintext = Buffer.from(payloadStr, 'utf-8');
  const ciphertext = Buffer.alloc(plaintext.length + sodium.crypto_secretbox_MACBYTES);
  sodium.crypto_secretbox_easy(ciphertext, plaintext, nonce, roomKey);
  sodium.sodium_memzero(plaintext);
  return JSON.stringify({ rk: 1, n: nonce.toString('base64'), c: ciphertext.toString('base64') });
}

/** True if a decrypted payload object is a private-room wrapper. */
export function isRoomWrapped(data) {
  return (
    data !== null &&
    typeof data === 'object' &&
    data.rk === 1 &&
    typeof data.n === 'string' &&
    typeof data.c === 'string'
  );
}

/**
 * Open the private-room layer. Returns the inner payload string, or null if
 * the wrapper is malformed or the key doesn't match (wrong/stale room key).
 */
export function decryptRoomPayload(data, roomKey) {
  if (!isRoomWrapped(data)) {
    return null;
  }
  try {
    const nonce = Buffer.from(data.n, 'base64');
    const ciphertext = Buffer.from(data.c, 'base64');
    if (
      nonce.length !== sodium.crypto_secretbox_NONCEBYTES ||
      ciphertext.length <= sodium.crypto_secretbox_MACBYTES
    ) {
      return null;
    }
    const plaintext = Buffer.alloc(ciphertext.length - sodium.crypto_secretbox_MACBYTES);
    if (!sodium.crypto_secretbox_open_easy(plaintext, ciphertext, nonce, roomKey)) {
      return null;
    }
    return plaintext.toString('utf-8');
  } catch {
    return null;
  }
}

/** Zero out room secrets when leaving a private room. */
export function freeRoomSecrets(secrets) {
  if (!secrets) {
    return;
  }
  if (Buffer.isBuffer(secrets.authSecretKey)) {
    sodium.sodium_memzero(secrets.authSecretKey);
  }
  if (Buffer.isBuffer(secrets.roomKey)) {
    sodium.sodium_memzero(secrets.roomKey);
  }
}
