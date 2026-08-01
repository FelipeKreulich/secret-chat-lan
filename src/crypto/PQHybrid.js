// Hybrid post-quantum layer: ML-KEM-768 (FIPS 203) mixed INTO the classical
// X25519 root key, never replacing it. Security is therefore >= the classical
// construction: an attacker must break BOTH to read a message. This is the
// conservative pattern Signal (PQXDH) and Apple (PQ3) adopted, and it targets
// "harvest now, decrypt later" — traffic recorded today stays unreadable to a
// future quantum adversary.
//
// sodium-native has no ML-KEM, so this uses @noble/post-quantum (audited,
// pure JS). Only the KEM comes from there; all symmetric crypto stays libsodium.
import sodium from 'sodium-native';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

export const PQ_PUBLIC_KEY_SIZE = 1184; // ML-KEM-768 encapsulation key
export const PQ_SECRET_KEY_SIZE = 2400; // ML-KEM-768 decapsulation key
export const PQ_CIPHERTEXT_SIZE = 1088;
export const PQ_SHARED_SECRET_SIZE = 32;

const PQ_MIX_CONTEXT = 'ciphermesh/pq-hybrid-v3';

/** Generate an ML-KEM-768 keypair. Buffers, to match the rest of the codebase. */
export function generatePQKeyPair() {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { publicKey: Buffer.from(publicKey), secretKey: Buffer.from(secretKey) };
}

/**
 * Encapsulate to a peer's ML-KEM public key.
 * @returns {{ ciphertext: Buffer, sharedSecret: Buffer }|null} null on bad input
 */
export function pqEncapsulate(peerPublicKey) {
  try {
    const pk = Buffer.isBuffer(peerPublicKey)
      ? peerPublicKey
      : Buffer.from(peerPublicKey, 'base64');
    if (pk.length !== PQ_PUBLIC_KEY_SIZE) {
      return null;
    }
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(new Uint8Array(pk));
    return { ciphertext: Buffer.from(cipherText), sharedSecret: Buffer.from(sharedSecret) };
  } catch {
    return null;
  }
}

/**
 * Decapsulate a ciphertext with our ML-KEM secret key.
 * @returns {Buffer|null} 32-byte shared secret, or null if it doesn't apply
 */
export function pqDecapsulate(ciphertext, secretKey) {
  try {
    const ct = Buffer.isBuffer(ciphertext) ? ciphertext : Buffer.from(ciphertext, 'base64');
    if (ct.length !== PQ_CIPHERTEXT_SIZE || !secretKey) {
      return null;
    }
    const ss = ml_kem768.decapsulate(new Uint8Array(ct), new Uint8Array(secretKey));
    return Buffer.from(ss);
  } catch {
    return null;
  }
}

/**
 * Fold a KEM shared secret into an existing root key:
 *   root' = BLAKE2b(root ‖ ss ‖ context)
 *
 * Because the classical root is an input, the result is at least as strong as
 * the classical key even if ML-KEM were broken outright. Returns a NEW locked
 * buffer; the caller owns zeroing the old root.
 */
export function mixPQIntoRoot(rootKey, sharedSecret) {
  const input = Buffer.concat([rootKey, sharedSecret, Buffer.from(PQ_MIX_CONTEXT, 'utf-8')]);
  const mixed = sodium.sodium_malloc(32);
  sodium.crypto_generichash(mixed, input);
  sodium.sodium_memzero(input);
  return mixed;
}
