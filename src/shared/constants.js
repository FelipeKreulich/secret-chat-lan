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
