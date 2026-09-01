import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import sodium from 'sodium-native';
import { padMessage } from '../src/crypto/MessageCrypto.js';
import { KeyManager } from '../src/crypto/KeyManager.js';
import {
  deriveRoomSecrets,
  signRoomChallenge,
  verifyRoomChallenge,
  freeRoomSecrets,
} from '../src/crypto/RoomKey.js';
import { mixPQIntoRoot } from '../src/crypto/PQHybrid.js';

/**
 * The corpus is a contract, not a snapshot.
 *
 * docs/PROTOCOL.md says what the wire looks like; this file says what the
 * derivations produce. A browser client or a second relay that gets a context
 * string, a bucket table or a byte order subtly wrong does not fail loudly —
 * it produces ciphertext the other side cannot open, or agrees on something
 * weaker than intended. So every value here is recomputed from the code and
 * compared, which means the corpus cannot drift from the implementation and
 * the implementation cannot drift from what a second one was built against.
 */
const vectors = JSON.parse(
  readFileSync(new URL('./vectors/protocol.json', import.meta.url), 'utf-8'),
);

const hex = (buf) => Buffer.from(buf).toString('hex');

describe('protocol vectors', () => {
  test('the file is what the generator produces', () => {
    assert.doesNotThrow(
      () => execFileSync('node', ['scripts/generate-vectors.mjs', '--check'], { stdio: 'pipe' }),
      'test/vectors/protocol.json is stale — run: npm run vectors:build',
    );
  });

  test('padding puts a message in the same bucket it always did', () => {
    // The bucket table is what hides how long a message was. A second
    // implementation that rounds differently leaks the difference, and one that
    // writes the length prefix differently cannot be unpadded at all.
    for (const c of vectors.padding.cases) {
      const padded = padMessage(Buffer.alloc(c.plaintextLength, 0x41));
      assert.equal(padded.length, c.paddedLength, `length ${c.plaintextLength}`);
      assert.equal(hex(padded.subarray(0, 2)), c.lengthPrefix);
      if (c.firstBodyByte !== null) {
        assert.equal(hex(padded.subarray(2, 3)), c.firstBodyByte);
      }
    }
  });

  test('a public key still fingerprints to the same string', () => {
    // This is what two people read out loud to each other. If it moves, every
    // fingerprint anyone ever wrote down is wrong.
    for (const c of vectors.fingerprints.cases) {
      const key = Buffer.from(c.publicKeyHex, 'hex');
      assert.equal(KeyManager.computeFingerprint(key), c.fingerprint);
    }
  });

  test('a room password still derives the same keys', () => {
    // Argon2id over a salt derived from the room name. Change the context
    // string, the limits or the split and everyone is locked out of their own
    // private room — with no error that says so.
    for (const c of vectors.roomSecrets.cases) {
      const secrets = deriveRoomSecrets(c.room, c.password);
      const signature = Buffer.from(c.challenge.signature, 'hex');
      assert.equal(hex(secrets.authPublicKey), c.authPublicKey, c.room);
      assert.equal(hex(secrets.roomKey), c.roomKey, c.room);

      // The signature is over room + server nonce + sessionId, so a captured
      // one cannot be replayed into another session or room.
      assert.equal(
        verifyRoomChallenge(
          secrets.authPublicKey,
          signature,
          c.room,
          c.challenge.nonceB64,
          c.challenge.sessionId,
        ),
        true,
      );
      assert.equal(
        verifyRoomChallenge(
          secrets.authPublicKey,
          signature,
          c.room,
          c.challenge.nonceB64,
          'someone-else',
        ),
        false,
        'a signature must not carry to another session',
      );
      // Ed25519 is deterministic, so signing again reproduces it exactly.
      assert.equal(
        hex(
          signRoomChallenge(
            secrets.authSecretKey,
            c.room,
            c.challenge.nonceB64,
            c.challenge.sessionId,
          ),
        ),
        c.challenge.signature,
      );
      freeRoomSecrets(secrets);
    }
  });

  test('the post-quantum secret is folded in the same way', () => {
    // Concatenation order and context string both matter: get either wrong and
    // the two sides agree on different roots while both think they succeeded.
    for (const c of vectors.pqMix.cases) {
      const mixed = mixPQIntoRoot(
        Buffer.from(c.rootKey, 'hex'),
        Buffer.from(c.sharedSecret, 'hex'),
      );
      assert.equal(hex(mixed), c.mixed);
      sodium.sodium_free(mixed);
    }
  });

  test('the corpus is readable without CipherMesh', () => {
    // The point of shipping it: another implementation must be able to consume
    // this file with nothing but a JSON parser and a hex decoder.
    for (const section of ['padding', 'fingerprints', 'roomSecrets', 'pqMix']) {
      assert.ok(vectors[section]?.cases?.length > 0, `${section} has cases`);
      assert.match(vectors[section].$comment, /\w/, `${section} explains itself`);
    }
    assert.match(vectors.$comment, /do not edit/);
  });
});
