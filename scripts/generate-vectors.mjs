#!/usr/bin/env node
/**
 * Test vectors for the derivations a second implementation has to reproduce.
 *
 * The wire protocol is written down in docs/PROTOCOL.md, but prose is not
 * enough to build against. Everything below is a choice CipherMesh made — a
 * context string, a bucket table, a byte layout — and a browser or a second
 * relay that gets one of them subtly wrong does not fail loudly. It fails by
 * producing ciphertext the other side cannot open, or worse, by agreeing on
 * something weaker than intended.
 *
 * So the corpus is inputs and expected outputs, in hex, with no CipherMesh code
 * needed to read it. Any implementation can be pointed at the same JSON.
 *
 * Regenerate with `npm run vectors:build`. test/protocol-vectors.test.js fails
 * when the code stops reproducing the file, so a derivation cannot be changed
 * by accident — only deliberately, by regenerating and explaining why in the
 * diff.
 *
 *   node scripts/generate-vectors.mjs           write test/vectors/protocol.json
 *   node scripts/generate-vectors.mjs --check   exit 1 if it is out of date
 */
import { writeFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import sodium from 'sodium-native';
import { padMessage } from '../src/crypto/MessageCrypto.js';
import { KeyManager } from '../src/crypto/KeyManager.js';
import { deriveRoomSecrets, signRoomChallenge, freeRoomSecrets } from '../src/crypto/RoomKey.js';
import { mixPQIntoRoot } from '../src/crypto/PQHybrid.js';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const target = join(root, 'test', 'vectors', 'protocol.json');

const hex = (buf) => Buffer.from(buf).toString('hex');

/** A deterministic 32-byte value, so the corpus is reproducible anywhere. */
function seed(label) {
  const out = Buffer.alloc(32);
  sodium.crypto_generichash(out, Buffer.from(label, 'utf-8'));
  return out;
}

/**
 * Message padding. The bucket table hides how long a message was; an
 * implementation that picks a different bucket leaks the difference, and one
 * that writes the length prefix differently cannot be unpadded at all.
 *
 * Only the first two bytes and the total length are pinned: the tail is random
 * by design, which is the point of it.
 */
function padding() {
  const cases = [];
  for (const length of [0, 1, 63, 64, 65, 200, 255, 256, 1000, 4096, 20000]) {
    const padded = padMessage(Buffer.alloc(length, 0x41));
    cases.push({
      plaintextLength: length,
      paddedLength: padded.length,
      lengthPrefix: hex(padded.subarray(0, 2)),
      firstBodyByte: length > 0 ? hex(padded.subarray(2, 3)) : null,
    });
  }
  return {
    $comment:
      'padMessage writes a 2-byte big-endian length, then the plaintext, then random filler to the next bucket. The filler is not pinned; the length and prefix are.',
    cases,
  };
}

/** The fingerprint people read out loud to each other. */
function fingerprints() {
  return {
    $comment:
      'KeyManager.computeFingerprint — what /verify shows and what a SAS comparison rests on.',
    cases: ['fingerprint-a', 'fingerprint-b', 'fingerprint-c'].map((label) => {
      const publicKey = seed(label);
      return {
        publicKeyHex: hex(publicKey),
        fingerprint: KeyManager.computeFingerprint(publicKey),
      };
    }),
  };
}

/**
 * Private rooms. The password never leaves the machine: both the signing key
 * that proves membership and the key that wraps room traffic come out of
 * Argon2id over a salt derived from the room name.
 */
function roomSecrets() {
  const cases = [];
  for (const [room, password] of [
    ['general', 'correct horse battery staple'],
    ['dev', 'p'],
    ['sala-com-acentuação', 'senha com espaços e ção'],
  ]) {
    const secrets = deriveRoomSecrets(room, password);
    const signature = signRoomChallenge(secrets.authSecretKey, room, 'bm9uY2U=', 'session-1');
    cases.push({
      room,
      password,
      authPublicKey: hex(secrets.authPublicKey),
      roomKey: hex(secrets.roomKey),
      challenge: { nonceB64: 'bm9uY2U=', sessionId: 'session-1', signature: hex(signature) },
    });
    freeRoomSecrets(secrets);
  }
  return {
    $comment:
      'deriveRoomSecrets: salt = BLAKE2b(context + room), then Argon2id at MODERATE limits over the password, split into an Ed25519 seed and a secretbox key. The signature binds room, server nonce and sessionId.',
    cases,
  };
}

/** Where the post-quantum half is folded into the ratchet root. */
function pqMix() {
  const cases = [];
  for (const [a, b] of [
    ['root-1', 'shared-1'],
    ['root-2', 'shared-2'],
  ]) {
    const mixed = mixPQIntoRoot(seed(a), seed(b));
    cases.push({ rootKey: hex(seed(a)), sharedSecret: hex(seed(b)), mixed: hex(mixed) });
    sodium.sodium_free(mixed);
  }
  return {
    $comment:
      'mixPQIntoRoot = BLAKE2b(rootKey || sharedSecret || context). Get the concatenation order or the context wrong and both sides agree on different roots.',
    cases,
  };
}

const corpus = {
  $comment:
    'Generated by scripts/generate-vectors.mjs — do not edit. Inputs and expected outputs for the derivations a second implementation must reproduce byte for byte. See docs/PROTOCOL.md for what they mean.',
  padding: padding(),
  fingerprints: fingerprints(),
  roomSecrets: roomSecrets(),
  pqMix: pqMix(),
};

const serialised = `${JSON.stringify(corpus, null, 2)}\n`;

if (process.argv.includes('--check')) {
  let current = '';
  try {
    current = readFileSync(target, 'utf-8');
  } catch {
    /* missing counts as out of date */
  }
  if (current !== serialised) {
    console.error('test/vectors/protocol.json is out of date — run: npm run vectors:build');
    process.exit(1);
  }
  console.log('test/vectors/protocol.json is up to date');
} else {
  writeFileSync(target, serialised);
  const counts = Object.entries(corpus)
    .filter(([, v]) => v && Array.isArray(v.cases))
    .map(([k, v]) => `${k}: ${v.cases.length}`)
    .join(', ');
  console.log(`test/vectors/protocol.json (${counts})`);
}
