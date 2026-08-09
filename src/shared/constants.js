export const PROTOCOL_VERSION = 2; // v2: sealed sender (encrypted_message carries `sealed`, no `from`)

// ── Capability negotiation ─────────────────────────────────────
// PROTOCOL_VERSION is an exact-equality gate, so it cannot express "newer, but
// still able to talk to you". Capabilities fill that gap: a client lists what it
// can do in JOIN, the relay hands the list on verbatim with the peer list, and a
// feature turns on only when every member of the room advertises it. Absent or
// empty means an older peer, which is the safe default rather than an error.
export const CAP = {
  // Group encryption on the relay path — one ciphertext for the whole room
  // instead of one sealed envelope per peer. See
  // docs/design/sender-keys-on-relay.md.
  //
  // From a client it means "I can *receive* a group message": I accept a sender
  // key over the pairwise channel and can decrypt what that chain produces.
  // From the relay it means "I can fan a room-addressed message out". Receive
  // and fan-out land a release before anyone sends, so that by the time a sender
  // exists, every advertised room can already read it.
  SENDER_KEYS: 'sk1',
};

// What this client advertises. SENDER_KEYS is honest here: the receive path
// exists. Nothing sends group messages yet.
export const OWN_CAPABILITIES = [CAP.SENDER_KEYS];

// What the relay advertises, in join_ack. A client cannot promise this on the
// relay's behalf — the fan-out is the relay's job — so a sender has to check the
// room *and* the hub it is sitting on before switching paths.
export const SERVER_CAPABILITIES = [CAP.SENDER_KEYS];

// Bounds. This list arrives from a public hub, so it is attacker-controlled.
export const MAX_CAPABILITIES = 16;
export const MAX_CAPABILITY_LENGTH = 24;

// Network
export const SERVER_PORT = 3600;
export const HEARTBEAT_INTERVAL_MS = 30_000;
export const RECONNECT_BASE_MS = 1_000;
export const RECONNECT_MAX_MS = 30_000;

// Limits
export const MAX_NICKNAME_LENGTH = 20;
export const MAX_PAYLOAD_SIZE = 65_536;
export const RATE_LIMIT_PER_SECOND = 30;
export const SESSION_TIMEOUT_MS = 300_000;

// Server hardening
export const MAX_CONNECTIONS_TOTAL = 500; // global socket cap
export const MAX_CONNECTIONS_PER_IP = 20; // per-source-IP socket cap
export const JOIN_TIMEOUT_MS = 15_000; // drop sockets that never JOIN
export const MESSAGE_RATE_LIMIT_PER_SECOND = 60; // per connection, ALL message types

// How fast one source may *open* connections, as opposed to how many it may
// hold. The concurrency cap never trips against churn — connect, handshake,
// disconnect, repeat — and every one of those attempts costs the relay an
// X25519 and an ML-KEM-768 operation while costing the client almost nothing.
export const CONNECTION_RATE_PER_MINUTE = 60;

// Bytes per second per connection, sustained. The message limit counts
// messages, and messages are padded into buckets, so a session at 60/s is a
// multi-megabit stream: bytes are the resource that actually runs out.
export const MAX_BYTES_PER_SECOND = 1_048_576;
// Burst allowance, so a file transfer is not mistaken for an attack. Must stay
// comfortably above MAX_PAYLOAD_SIZE — a burst smaller than one frame could
// never be paid for, and the connection would wedge instead of throttling.
export const MAX_BYTES_BURST = 4_194_304;

// Crypto sizes (libsodium Curve25519 + XSalsa20-Poly1305)
export const NONCE_SIZE = 24;
export const PUBLIC_KEY_SIZE = 32;
export const SECRET_KEY_SIZE = 32;
export const MAC_SIZE = 16;
export const SHARED_KEY_SIZE = 32;

// Nonce structure offsets
export const NONCE_TIMESTAMP_OFFSET = 0;
export const NONCE_TIMESTAMP_SIZE = 8;
export const NONCE_COUNTER_OFFSET = 8;
export const NONCE_COUNTER_SIZE = 4;
export const NONCE_RANDOM_OFFSET = 12;
export const NONCE_RANDOM_SIZE = 12;

// Anti-replay
export const NONCE_MAX_AGE_MS = 30_000;

// Offline queue
export const OFFLINE_QUEUE_MAX_PER_PEER = 100;
export const OFFLINE_QUEUE_MAX_AGE_MS = 3_600_000; // 1h
export const OFFLINE_QUEUE_MAX_TOTAL = 1000;

// Private rooms (password-protected, zero-knowledge)
export const ROOM_AUTH_PK_SIZE = 32; // Ed25519 verifier public key
export const ROOM_AUTH_SIG_SIZE = 64; // Ed25519 detached signature
export const ROOM_CHALLENGE_NONCE_SIZE = 24;
export const ROOM_CHALLENGE_TTL_MS = 60_000; // challenge must be answered within this
export const ROOM_AUTH_MAX_FAILS = 5; // wrong-password attempts per connection…
export const ROOM_AUTH_FAIL_WINDOW_MS = 60_000; // …within this window

// Message padding (anti-metadata): every ciphertext is padded up to one of
// these bucket sizes so the relay can't read the true plaintext length.
export const MESSAGE_PAD_BUCKETS = [128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768];

// Cover traffic (anti-metadata): when enabled, decoy messages are sent at
// jittered intervals so an observer can't tell active chatting from idle.
export const COVER_MIN_MS = 20_000; // shortest gap between decoys (jitter mode)
export const COVER_MAX_MS = 60_000; // longest gap between decoys (jitter mode)
export const COVER_MAX_FILLER = 2000; // random filler bytes → varied padding buckets
// Constant-rate mode: fixed cadence. Each slot carries a queued real message or,
// if none, a decoy — so the wire rate is steady whether you chat or idle.
export const COVER_CONSTANT_MS = 3000;

// Key rotation
export const KEY_ROTATION_INTERVAL_MS = 3_600_000; // 1h
export const KEY_ROTATION_GRACE_MS = 30_000; // 30s — keep old key for in-flight msgs

// Double Ratchet (PFS)
export const RATCHET_MAX_SKIP = 100;
export const RATCHET_SKIP_KEY_MAX_AGE_MS = 60_000; // 60s

// File transfer
export const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
// 16KB raw. The chunk is base64'd into the JSON payload, encrypted, then the
// ciphertext is base64'd again into the wire message — a ~1.78x expansion. At
// 16KB the plaintext stays under padMessage's 2-byte length field (65535) and
// the final wire frame (~29KB) stays well under MAX_PAYLOAD_SIZE.
export const FILE_CHUNK_SIZE = 16_384;

// Emoji map for reactions and inline shortcodes
export const EMOJI_MAP = {
  ':thumbsup:': '\uD83D\uDC4D',
  ':heart:': '\u2764\uFE0F',
  ':laugh:': '\uD83D\uDE02',
  ':fire:': '\uD83D\uDD25',
  ':check:': '\u2705',
  ':x:': '\u274C',
  ':eyes:': '\uD83D\uDC40',
  ':clap:': '\uD83D\uDC4F',
  ':smile:': '\uD83D\uDE04',
  ':sad:': '\uD83D\uDE22',
  ':cry:': '\uD83D\uDE2D',
  ':party:': '\uD83C\uDF89',
  ':rocket:': '\uD83D\uDE80',
  ':100:': '\uD83D\uDCAF',
  ':wave:': '\uD83D\uDC4B',
  ':thinking:': '\uD83E\uDD14',
  ':skull:': '\uD83D\uDC80',
  ':pray:': '\uD83D\uDE4F',
  ':ok:': '\uD83D\uDC4C',
  ':poop:': '\uD83D\uDCA9',
  ':thumbsdown:': '\uD83D\uDC4E',
  ':wink:': '\uD83D\uDE09',
  ':cool:': '\uD83D\uDE0E',
  ':angry:': '\uD83D\uDE20',
  ':love:': '\uD83D\uDE0D',
  ':kiss:': '\uD83D\uDE18',
  ':tongue:': '\uD83D\uDE1B',
  ':shush:': '\uD83E\uDD2B',
  ':star:': '\u2B50',
  ':warning:': '\u26A0\uFE0F',
  ':question:': '\u2753',
  ':bulb:': '\uD83D\uDCA1',
  ':lock:': '\uD83D\uDD12',
  ':key:': '\uD83D\uDD11',
  ':bell:': '\uD83D\uDD14',
  ':tada:': '\uD83C\uDF8A',
  ':coffee:': '\u2615',
  ':beer:': '\uD83C\uDF7A',
  ':pizza:': '\uD83C\uDF55',
  ':ghost:': '\uD83D\uDC7B',
  ':robot:': '\uD83E\uDD16',
  ':alien:': '\uD83D\uDC7D',
  ':sun:': '\u2600\uFE0F',
  ':moon:': '\uD83C\uDF19',
  ':zap:': '\u26A1',
  ':boom:': '\uD83D\uDCA5',
  ':muscle:': '\uD83D\uDCAA',
  ':point_up:': '\u261D\uFE0F',
  ':raised_hands:': '\uD83D\uDE4C',
  ':facepalm:': '\uD83E\uDD26',
  ':shrug:': '\uD83E\uDD37',
};
