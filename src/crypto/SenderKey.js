import sodium from 'sodium-native';
import { NONCE_SIZE } from '../shared/constants.js';
import { padMessage, unpadSecure } from './MessageCrypto.js';

// ── Sender Keys: real group cryptography ────────────────────────
// Each sender owns a symmetric ratchet chain per room. A message is encrypted
// ONCE with the next message key and the same ciphertext is broadcast to every
// member (O(1) instead of one pairwise encryption per peer). Members decrypt
// with the sender's chain, which was distributed once over the pairwise channel.
// Forward secrecy comes from ratcheting the chain forward every message and
// rotating the whole chain on membership changes.

const KEY_SIZE = 32;
const MSG_KEY_TAG = Buffer.from([0x01]);
const CHAIN_KEY_TAG = Buffer.from([0x02]);
const DEFAULT_MAX_SKIP = 1000; // bound out-of-order / skipped message keys
const KEY_ID_SIZE = 16;

// Release a key allocated with sodium_malloc.
//
// `sodium_memzero` alone is not enough, and the difference is not academic.
// sodium_malloc'd pages are **mlock'd**, and an operating system caps how much
// a process may lock at once — RLIMIT_MEMLOCK, which on Linux is small and on
// macOS is typically unlimited. Zeroing a key leaves its pages locked until the
// garbage collector happens to run the buffer's finaliser, so a process that
// derives keys faster than it collects them walks into an allocation failure it
// never sees coming: sodium_malloc returns NULL, and the crash lands on whatever
// unrelated call allocated next.
//
// sodium_free zeroes before releasing, so this is strictly stronger than the
// memzero it replaces. Null-safe and idempotent by convention: every caller
// drops its reference immediately after, so nothing can reach freed memory.
function freeKey(buf) {
  if (buf) {
    sodium.sodium_free(buf);
  }
}

// An opaque label for a sender chain, handed out with the distribution.
//
// On the relay path a group message arrives by fan-out with no sender on it —
// the relay must not stamp one, or it would be asserting an identity that today
// is only ever carried sealed inside the envelope. So the packet names its
// *chain* instead of its sender, and only members who hold the distribution can
// map the two. To the relay it is a random string; it already knows which socket
// sent the frame, so this tells it nothing new. It is drawn fresh on every
// rotate(), so it never outlives the chain it labels.
function newKeyId() {
  const buf = Buffer.alloc(KEY_ID_SIZE);
  sodium.randombytes_buf(buf);
  return buf.toString('base64');
}

// ── Per-sender signatures ───────────────────────────────────────
// A sender key is symmetric: every member of the room holds the chain that
// decrypts a given sender, which means every member can also *produce*
// ciphertext on it. Without something asymmetric on top, "Alice said this" is
// only ever "somebody in this room said this" — and on a public relay, where
// `general` has no owner and no admission control, that is a much wider set of
// somebodies than in a P2P mesh.
//
// So each sender also holds an Ed25519 keypair for the life of its chain. The
// public half travels in the distribution, over the pairwise sealed channel that
// already authenticates who sent it; every packet carries a detached signature.
// Forging a member now needs their signing key, not just membership.
function newSigningKeypair() {
  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
  const secretKey = sodium.sodium_malloc(sodium.crypto_sign_SECRETKEYBYTES);
  sodium.crypto_sign_keypair(publicKey, secretKey);
  return { publicKey, secretKey };
}

// What the signature covers. Every field the relay could tamper with or replay
// across chains: the label, the position in the chain, and the box itself.
// Length-prefixed so no two different packets can serialise to the same bytes.
function signedBytes({ keyId, counter, ciphertext, nonce }) {
  const parts = [keyId, String(counter), ciphertext, nonce];
  return Buffer.from(parts.map((p) => `${p.length}:${p}`).join('|'), 'utf-8');
}

function decodeSignPk(b64) {
  if (typeof b64 !== 'string') {
    return null;
  }
  let buf;
  try {
    buf = Buffer.from(b64, 'base64');
  } catch {
    return null;
  }
  return buf.length === sodium.crypto_sign_PUBLICKEYBYTES ? buf : null;
}

// A single sender's ratchet chain. Used to *send* (deriveNext) when it's your
// own chain, or to *receive* (messageKeyFor) when it's a peer's distributed one.
export class SenderChain {
  #chainKey;
  #counter;
  #skipped; // Map<counter, messageKey> for out-of-order receipt
  #maxSkip;

  constructor(chainKey = null, counter = 0, maxSkip = DEFAULT_MAX_SKIP) {
    this.#chainKey = sodium.sodium_malloc(KEY_SIZE);
    if (chainKey) {
      chainKey.copy(this.#chainKey);
    } else {
      sodium.randombytes_buf(this.#chainKey);
    }
    this.#counter = counter;
    this.#skipped = new Map();
    this.#maxSkip = maxSkip;
  }

  // Derive the current message key and ratchet the chain forward one step.
  #step() {
    const messageKey = sodium.sodium_malloc(KEY_SIZE);
    sodium.crypto_generichash(messageKey, MSG_KEY_TAG, this.#chainKey);
    const nextChainKey = sodium.sodium_malloc(KEY_SIZE);
    sodium.crypto_generichash(nextChainKey, CHAIN_KEY_TAG, this.#chainKey);
    const spent = this.#chainKey;
    this.#chainKey = nextChainKey;
    freeKey(spent); // released, not merely zeroed — the hot path, once per message
    return messageKey;
  }

  // Sending: next message key + its counter.
  deriveNext() {
    const counter = this.#counter;
    const messageKey = this.#step();
    this.#counter++;
    return { messageKey, counter };
  }

  // Receiving: the message key at `targetCounter`, caching skipped keys for
  // out-of-order delivery. Returns null on replay (already consumed) or if the
  // gap exceeds maxSkip. The caller owns the returned key and must release it —
  // groupDecrypt does, on every path including the failures.
  messageKeyFor(targetCounter) {
    if (this.#skipped.has(targetCounter)) {
      const key = this.#skipped.get(targetCounter);
      this.#skipped.delete(targetCounter);
      return key;
    }
    if (targetCounter < this.#counter) {
      return null; // already consumed → replay
    }
    if (targetCounter - this.#counter > this.#maxSkip) {
      return null; // too far ahead
    }
    while (this.#counter < targetCounter) {
      this.#skipped.set(this.#counter, this.#step());
      this.#counter++;
    }
    const messageKey = this.#step();
    this.#counter++;
    return messageKey;
  }

  // Serialise the chain state so it can be handed to a new member (over the
  // encrypted pairwise channel). Never send this in the clear.
  serialize() {
    return { chainKey: Buffer.from(this.#chainKey).toString('base64'), counter: this.#counter };
  }

  static deserialize({ chainKey, counter }) {
    return new SenderChain(Buffer.from(chainKey, 'base64'), counter);
  }

  destroy() {
    freeKey(this.#chainKey);
    this.#chainKey = null;
    for (const key of this.#skipped.values()) {
      freeKey(key);
    }
    this.#skipped.clear();
  }
}

// Encrypt with a one-shot message key (length-padded, like the pairwise paths).
export function groupEncrypt(messageKey, plaintext) {
  const message = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf-8');
  const padded = padMessage(message);
  const nonce = Buffer.alloc(NONCE_SIZE);
  sodium.randombytes_buf(nonce);
  const ciphertext = Buffer.alloc(padded.length + sodium.crypto_secretbox_MACBYTES);
  sodium.crypto_secretbox_easy(ciphertext, padded, nonce, messageKey);
  sodium.sodium_memzero(padded);
  freeKey(messageKey);
  return { ciphertext, nonce };
}

export function groupDecrypt(messageKey, ciphertext, nonce) {
  if (ciphertext.length < sodium.crypto_secretbox_MACBYTES) {
    freeKey(messageKey);
    return null;
  }
  const padded = Buffer.alloc(ciphertext.length - sodium.crypto_secretbox_MACBYTES);
  const ok = sodium.crypto_secretbox_open_easy(padded, ciphertext, nonce, messageKey);
  freeKey(messageKey);
  if (!ok) {
    sodium.sodium_memzero(padded);
    return null;
  }
  return unpadSecure(padded);
}

// A per-room group session: your own sending chain + one receiving chain per
// member. encrypt() runs once; every member decrypt()s the same ciphertext.
export class GroupSession {
  #own;
  #ownKeyId;
  #signPk; // Ed25519 — proves *which member* wrote a packet
  #signSk;
  #members; // Map<memberId, SenderChain>
  #byKeyId; // Map<keyId, memberId> — which chain opens an incoming packet
  #memberSignPk; // Map<memberId, Buffer> — who is allowed to have written it

  constructor() {
    this.#own = new SenderChain();
    this.#ownKeyId = newKeyId();
    ({ publicKey: this.#signPk, secretKey: this.#signSk } = newSigningKeypair());
    this.#members = new Map();
    this.#byKeyId = new Map();
    this.#memberSignPk = new Map();
  }

  encrypt(plaintext) {
    const { messageKey, counter } = this.#own.deriveNext();
    const { ciphertext, nonce } = groupEncrypt(messageKey, plaintext);
    const packet = {
      keyId: this.#ownKeyId,
      counter,
      ciphertext: ciphertext.toString('base64'),
      nonce: nonce.toString('base64'),
    };
    const signature = Buffer.alloc(sodium.crypto_sign_BYTES);
    sodium.crypto_sign_detached(signature, signedBytes(packet), this.#signSk);
    packet.signature = signature.toString('base64');
    return packet;
  }

  decrypt(memberId, { keyId, counter, ciphertext, nonce, signature }) {
    const chain = this.#members.get(memberId);
    if (!chain) {
      return null;
    }

    // Verify BEFORE touching the chain. Two reasons, and the second is the one
    // that is easy to miss: a bad signature must not be able to advance the
    // ratchet or fill the skipped-key cache, or an unauthenticated packet with a
    // large counter becomes a way to make the receiver derive a thousand keys.
    if (!this.#verify(memberId, { keyId, counter, ciphertext, nonce, signature })) {
      return null;
    }

    const messageKey = chain.messageKeyFor(counter);
    if (!messageKey) {
      return null;
    }
    return groupDecrypt(
      messageKey,
      Buffer.from(ciphertext, 'base64'),
      Buffer.from(nonce, 'base64'),
    );
  }

  #verify(memberId, packet) {
    const signPk = this.#memberSignPk.get(memberId);
    if (!signPk || typeof packet.signature !== 'string' || typeof packet.keyId !== 'string') {
      return false;
    }
    // The label on the packet has to be the one this member distributed.
    // Verifying against the stored label instead would leave keyId outside
    // everything that protects it — the AEAD does not cover it either — so
    // decrypt() could be talked into checking one member's signature against
    // another member's label.
    if (this.#byKeyId.get(packet.keyId) !== memberId) {
      return false;
    }
    let sig;
    try {
      sig = Buffer.from(packet.signature, 'base64');
    } catch {
      return false;
    }
    if (sig.length !== sodium.crypto_sign_BYTES) {
      return false;
    }
    return sodium.crypto_sign_verify_detached(sig, signedBytes(packet), signPk);
  }

  // The distribution message to hand a (new) member so they can decrypt you.
  // `keyId` labels the chain; `signPk` is what stops any *other* member using
  // that chain to write in your name.
  distribution() {
    return {
      ...this.#own.serialize(),
      keyId: this.#ownKeyId,
      signPk: this.#signPk.toString('base64'),
    };
  }

  // Which member does an incoming packet's keyId belong to? Null for a label we
  // were never given a distribution for — an unknown sender, or one that
  // rotated without telling us yet.
  memberForKeyId(keyId) {
    return this.#byKeyId.get(keyId) ?? null;
  }

  get keyId() {
    return this.#ownKeyId;
  }

  addMember(memberId, distribution) {
    const existing = this.#members.get(memberId);
    if (existing) {
      existing.destroy();
    }
    // Drop any label this member held before — a redistribution after rotate()
    // replaces the chain, and leaving the old keyId mapped would route the
    // member's next packet to a chain that can no longer open it.
    this.#forgetKeyIdsOf(memberId);
    this.#members.set(memberId, SenderChain.deserialize(distribution));
    if (typeof distribution?.keyId === 'string') {
      this.#byKeyId.set(distribution.keyId, memberId);
    }
    // A distribution without a usable signing key leaves the member registered
    // but unreadable: #verify fails closed, so nothing they send is accepted.
    // Better a member who cannot be heard than one who cannot be attributed.
    const signPk = decodeSignPk(distribution?.signPk);
    if (signPk) {
      this.#memberSignPk.set(memberId, signPk);
    } else {
      this.#memberSignPk.delete(memberId);
    }
  }

  // Returns whether this actually removed a member. Callers rotate on a real
  // membership change and must not rotate on a departure they have already
  // handled: every rotation costs a redistribution to everyone remaining, and a
  // redistribution that crosses an incoming message is a message the recipient
  // has to buffer.
  removeMember(memberId) {
    const chain = this.#members.get(memberId);
    const had = this.#members.has(memberId) || this.#memberSignPk.has(memberId);
    if (chain) {
      chain.destroy();
      this.#members.delete(memberId);
    }
    this.#forgetKeyIdsOf(memberId);
    this.#memberSignPk.delete(memberId);
    return had;
  }

  #forgetKeyIdsOf(memberId) {
    for (const [id, owner] of this.#byKeyId) {
      if (owner === memberId) {
        this.#byKeyId.delete(id);
      }
    }
  }

  hasMember(memberId) {
    return this.#members.has(memberId);
  }

  // Rotate your own chain (forward secrecy on membership change). Callers must
  // redistribute the new distribution() to every member afterwards.
  rotate() {
    this.#own.destroy();
    this.#own = new SenderChain();
    this.#ownKeyId = newKeyId();
    // The signing key rotates with the chain it authenticates. Keeping it would
    // let anyone holding the old public key keep attributing new packets to a
    // chain that was rotated precisely because the room membership changed.
    //
    // Released rather than zeroed: rotation runs on every membership change, so
    // a room with any churn would otherwise accumulate locked pages for the life
    // of the session.
    freeKey(this.#signSk);
    ({ publicKey: this.#signPk, secretKey: this.#signSk } = newSigningKeypair());
  }

  destroy() {
    this.#own.destroy();
    freeKey(this.#signSk);
    this.#signSk = null;
    for (const chain of this.#members.values()) {
      chain.destroy();
    }
    this.#members.clear();
    this.#byKeyId.clear();
    this.#memberSignPk.clear();
  }
}
