export const PROTOCOL_VERSION = 1;

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

// Message padding (anti-metadata)
export const MESSAGE_PAD_BUCKETS = [128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768];

// Key rotation
export const KEY_ROTATION_INTERVAL_MS = 3_600_000; // 1h
export const KEY_ROTATION_GRACE_MS = 30_000; // 30s — keep old key for in-flight msgs

// Double Ratchet (PFS)
export const RATCHET_MAX_SKIP = 100;
export const RATCHET_SKIP_KEY_MAX_AGE_MS = 60_000; // 60s

// File transfer
export const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
export const FILE_CHUNK_SIZE = 49_152; // 48KB — fits in 64KB after encrypt + base64

// Emoji map for reactions
export const EMOJI_MAP = {
  ':thumbsup:': '\uD83D\uDC4D',
  ':heart:': '\u2764\uFE0F',
  ':laugh:': '\uD83D\uDE02',
  ':fire:': '\uD83D\uDD25',
  ':check:': '\u2705',
  ':x:': '\u274C',
  ':eyes:': '\uD83D\uDC40',
  ':clap:': '\uD83D\uDC4F',
};
