import { COVER_MIN_MS, COVER_MAX_MS, COVER_MAX_FILLER } from './constants.js';

// Cover traffic hides *when* and *how much* you chat from a relay/observer that
// can already only see ciphertext. Real messages are padded to fixed buckets
// (MessageCrypto.padMessage), so a decoy with random filler is indistinguishable
// from a real message on the wire. Decoys are dropped silently by the receiver.

/**
 * Jittered delay (ms) until the next decoy — uniform in [min, max].
 * `rand` is injectable for deterministic tests.
 */
export function nextCoverDelay(rand = Math.random, min = COVER_MIN_MS, max = COVER_MAX_MS) {
  return Math.round(min + rand() * (max - min));
}

/**
 * Build a decoy payload. The random filler varies the plaintext length so the
 * encrypted+padded decoy lands across the same buckets as real chat messages.
 * @param {number} now - timestamp (Date.now())
 * @param {() => number} rand - injectable RNG for tests
 */
export function coverPayload(now, rand = Math.random) {
  const fillerLen = Math.floor(rand() * COVER_MAX_FILLER);
  return JSON.stringify({
    action: 'cover',
    sentAt: now,
    x: 'x'.repeat(fillerLen), // opaque filler; the receiver ignores it
  });
}

/** True if a decoded payload is a decoy that should be dropped without any effect. */
export function isCover(data) {
  return !!data && data.action === 'cover';
}
