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
    sodium.sodium_memzero(this.#chainKey);
    this.#chainKey = nextChainKey;
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
  // gap exceeds maxSkip. The caller must sodium_memzero the returned key.
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
    sodium.sodium_memzero(this.#chainKey);
    for (const key of this.#skipped.values()) {
      sodium.sodium_memzero(key);
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
  sodium.sodium_memzero(messageKey);
  return { ciphertext, nonce };
}

export function groupDecrypt(messageKey, ciphertext, nonce) {
  if (ciphertext.length < sodium.crypto_secretbox_MACBYTES) {
    sodium.sodium_memzero(messageKey);
    return null;
  }
  const padded = Buffer.alloc(ciphertext.length - sodium.crypto_secretbox_MACBYTES);
  const ok = sodium.crypto_secretbox_open_easy(padded, ciphertext, nonce, messageKey);
  sodium.sodium_memzero(messageKey);
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
  #members; // Map<memberId, SenderChain>
  #byKeyId; // Map<keyId, memberId> — which chain opens an incoming packet

  constructor() {
    this.#own = new SenderChain();
    this.#ownKeyId = newKeyId();
    this.#members = new Map();
    this.#byKeyId = new Map();
  }

  encrypt(plaintext) {
    const { messageKey, counter } = this.#own.deriveNext();
    const { ciphertext, nonce } = groupEncrypt(messageKey, plaintext);
    return {
      keyId: this.#ownKeyId,
      counter,
      ciphertext: ciphertext.toString('base64'),
      nonce: nonce.toString('base64'),
    };
  }

  decrypt(memberId, { counter, ciphertext, nonce }) {
    const chain = this.#members.get(memberId);
    if (!chain) {
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

  // The distribution message to hand a (new) member so they can decrypt you.
  // `keyId` rides along so the member can recognise packets from this chain.
  distribution() {
    return { ...this.#own.serialize(), keyId: this.#ownKeyId };
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
  }

  removeMember(memberId) {
    const chain = this.#members.get(memberId);
    if (chain) {
      chain.destroy();
      this.#members.delete(memberId);
    }
    this.#forgetKeyIdsOf(memberId);
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
  }

  destroy() {
    this.#own.destroy();
    for (const chain of this.#members.values()) {
      chain.destroy();
    }
    this.#members.clear();
    this.#byKeyId.clear();
  }
}
