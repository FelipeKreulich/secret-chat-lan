import sodium from 'sodium-native';

// ── Sealed sender: anonymise the SENDER to the relay ────────────
// The zero-knowledge relay routes by `to` and never needs `from`. Sealed sender
// removes `from` from the wire envelope and instead carries the sender's
// identity inside a libsodium *sealed box* (crypto_box_seal): the sender uses a
// throwaway ephemeral keypair to encrypt to the recipient's static public key,
// so the ciphertext is anonymous — only the recipient's secret key opens it, and
// nothing in it identifies the sender to the relay. The recipient opens it,
// learns `from`, then decrypts the inner (already E2E-encrypted) payload as usual.
// (Recipient identity is still visible to the relay — that's inherent to routing.)

// Anonymous seal of arbitrary bytes to a recipient public key.
export function seal(inner, recipientPublicKey) {
  const message = Buffer.isBuffer(inner) ? inner : Buffer.from(inner, 'utf-8');
  const ciphertext = Buffer.alloc(message.length + sodium.crypto_box_SEALBYTES);
  sodium.crypto_box_seal(ciphertext, message, recipientPublicKey);
  return ciphertext;
}

// Open a sealed box; returns the plaintext Buffer, or null on failure/tamper.
export function unseal(sealedCiphertext, recipientPublicKey, recipientSecretKey) {
  if (sealedCiphertext.length < sodium.crypto_box_SEALBYTES) {
    return null;
  }
  const out = Buffer.alloc(sealedCiphertext.length - sodium.crypto_box_SEALBYTES);
  const ok = sodium.crypto_box_seal_open(
    out,
    sealedCiphertext,
    recipientPublicKey,
    recipientSecretKey,
  );
  if (!ok) {
    sodium.sodium_memzero(out);
    return null;
  }
  return out;
}

// Wrap an already-encrypted payload plus the sender's identity so the relay
// can't see who sent it. Returns base64 for the wire `payload.sealed` field.
export function sealEnvelope(from, payload, recipientPublicKey) {
  const inner = Buffer.from(JSON.stringify({ from, payload }), 'utf-8');
  return seal(inner, recipientPublicKey).toString('base64');
}

// Open a sealed envelope → { from, payload }, or null if it isn't for us.
export function openEnvelope(sealedB64, recipientPublicKey, recipientSecretKey) {
  const opened = unseal(Buffer.from(sealedB64, 'base64'), recipientPublicKey, recipientSecretKey);
  if (!opened) {
    return null;
  }
  try {
    return JSON.parse(opened.toString('utf-8'));
  } catch {
    return null;
  }
}
