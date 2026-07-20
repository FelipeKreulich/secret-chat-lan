# SecureLAN Chat — Complete Technical Documentation

> Secure chat for a local area network (LAN) with real end-to-end encryption (E2EE).
> The server **never** has access to the content of messages.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Technology Stack](#2-technology-stack)
3. [Directory Structure](#3-directory-structure)
4. [Responsibility of Each Module](#4-responsibility-of-each-module)
5. [Data Model and Payloads](#5-data-model-and-payloads)
6. [Detailed Cryptographic Flow](#6-detailed-cryptographic-flow)
7. [Handshake Protocol](#7-handshake-protocol)
8. [Step-by-Step Communication Flow](#8-step-by-step-communication-flow)
9. [Initialization Strategy](#9-initialization-strategy)
10. [Security — Threat Analysis](#10-security--threat-analysis)
11. [Future Improvements](#11-future-improvements)
12. [Glossary](#12-glossary)

---

## 1. Overview

### What it is

SecureLAN Chat is an instant messaging system designed to operate **exclusively within a local area network (LAN)**. It uses end-to-end encryption (E2EE) based on **Curve25519 + XSalsa20-Poly1305** (via libsodium), ensuring that the server acts only as a **blind relay** — it forwards bytes it cannot read.

### Core Principle

```
Cliente A                  Servidor                  Cliente B
   |                          |                          |
   |--- payload cifrado ----->|                          |
   |                          |--- payload cifrado ----->|
   |                          |                          |
   |  O servidor NAO possui   |                          |
   |  a chave para decifrar   |                          |
```

The server knows **only**:
- Who is connected (nickname + session ID)
- Who sent to whom (routing)
- The size of the encrypted payload
- Connection timestamps

The server **never** knows:
- The content of messages
- Private keys
- Derived shared keys

### Topology

```
                    ┌──────────────┐
                    │   Servidor   │
                    │  (Relay)     │
                    │  :3600       │
                    └──────┬───────┘
                           │ WebSocket
              ┌────────────┼────────────┐
              │            │            │
        ┌─────┴─────┐ ┌───┴───┐ ┌─────┴─────┐
        │ Cliente A  │ │  ...  │ │ Cliente N  │
        │ (Terminal) │ │       │ │ (Terminal) │
        └───────────┘ └───────┘ └───────────┘
```

This is the **star** topology (star topology) — the default mode. All clients connect to the central server. Messages are encrypted before leaving the client and decrypted only at the destination client.

### P2P Topology (alternative mode)

```
        ┌───────────┐
        │ Cliente A  │
        │ (Terminal) │
        └─────┬─────┘
              │ WebSocket direto
    ┌─────────┼──────────┐
    │                    │
┌───┴───┐          ┌────┴────┐
│  ...  │          │ Cliente N│
│       │          │(Terminal)│
└───────┘          └─────────┘
```

In P2P mode (`npm run p2p`), peers discover each other via mDNS on the LAN and connect directly without a central server. Same E2E encryption.

---

## 2. Technology Stack

### Production Dependencies

| Package | Version | Role | Why this lib? |
|--------|--------|-------|-------------------|
| **ws** | ^8.18 | WebSocket server/client | The most mature and performant WebSocket implementation for Node.js. Zero dependencies. Natively supports binary frames (essential for encrypted payloads). Used by thousands of projects in production. |
| **sodium-native** | ^4.3 | Cryptography | Native binding of **libsodium** for Node.js. Runs in compiled C (not pure JS), offering real performance and audited security. libsodium is considered the most secure and easy-to-use modern cryptographic library. Used by Signal, Discord, Wireguard. |
| **blessed** | ^0.1.81 | Terminal UI | A library for building rich interfaces in the terminal. Supports layouts with boxes, inputs, scrolling, colors, borders — similar to ncurses but in JS. Lets you create a modern app-style UI without leaving the terminal. |
| **chalk** | ^5.4 | Terminal colors | Colored text formatting in the terminal. Used to highlight nicks, timestamps, errors, status. ESM-only in v5 (compatible with our `"type": "module"`). |
| **play-sound** | ^1.1 | Audio | Plays audio files (mp3) for sound notifications. Uses the OS's native players (mplayer, aplay, cmdmp3). |

### Why sodium-native and not tweetnacl?

| Criterion | sodium-native | tweetnacl |
|----------|--------------|-----------|
| Implementation | C (compiled libsodium) | Pure JavaScript |
| Performance | ~100x faster | Slow |
| Audit | Formally audited | Audited but pure JS |
| Secure memory | Yes (`sodium.sodium_malloc`) | No |
| Constant-time | Guaranteed by the C code | Best-effort in JS |
| Side-channel resistance | High | Low (the JS engine may optimize) |

**sodium-native** allocates secure memory that is:
- Protected against swap (mlock)
- Zeroed when freed (sodium_memzero)
- Protected against reads by other processes

### Development Dependencies

| Package | Role |
|--------|-------|
| **eslint** ^9.17 | Linting — ensures code quality and consistency |
| **@eslint/js** ^9.17 | ESLint's recommended base configuration |
| **globals** ^15.14 | Globals definitions (node, browser) for ESLint |
| **prettier** ^3.4 | Automatic formatting — consistent code with no style debates |

### Node.js >= 20

Minimum requirement: Node.js 20 LTS. Reasons:
- Native `node:test` (no Jest/Mocha)
- `node:crypto` with modern APIs
- Native `--watch` (no nodemon)
- Stable ESM
- Improved V8 performance

---

## 3. Directory Structure

```
securelan-chat/
│
├── docs/
│   └── ARCHITECTURE.md          # Este documento
│
├── src/
│   ├── server/
│   │   ├── index.js             # Entry point do servidor
│   │   ├── WebSocketServer.js   # Gerencia conexoes WebSocket
│   │   ├── SessionManager.js    # Controla sessoes ativas (clientes conectados)
│   │   ├── MessageRouter.js     # Roteia payloads cifrados entre clientes
│   │   ├── OfflineQueue.js      # Fila de mensagens para peers offline
│   │   └── CertManager.js      # Geracao e carregamento de certs TLS
│   │
│   ├── client/
│   │   ├── index.js             # Entry point do cliente
│   │   ├── UI.js                # Interface blessed (layout, rendering)
│   │   ├── Connection.js        # Conexao WebSocket com o servidor
│   │   ├── ChatController.js    # Logica central: conecta UI + Connection + Crypto
│   │   └── FileTransfer.js     # Envio/recepcao de arquivos cifrados (chunks)
│   │
│   ├── crypto/
│   │   ├── KeyManager.js        # Gera e gerencia pares de chaves (em memoria)
│   │   ├── MessageCrypto.js     # Cifra e decifra mensagens (crypto_box_easy)
│   │   ├── Handshake.js         # Protocolo de troca de chaves publicas
│   │   ├── NonceManager.js      # Geracao e validacao de nonces
│   │   ├── DoubleRatchet.js     # PFS via Double Ratchet (DH ratchet + KDF chains)
│   │   ├── TrustStore.js        # TOFU + SAS (persistencia de fingerprints)
│   │   └── StateManager.js      # Persistencia cifrada de estado (Argon2id + secretbox)
│   │
│   ├── p2p/
│   │   ├── index.js             # Entry point do modo P2P
│   │   ├── Discovery.js         # mDNS discovery via bonjour-service
│   │   ├── PeerServer.js        # WebSocket server local (porta aleatoria)
│   │   ├── PeerConnectionManager.js # Gerencia conexoes outbound/inbound
│   │   └── P2PChatController.js # Orquestrador P2P (crypto + UI + peers)
│   │
│   ├── protocol/
│   │   ├── messages.js          # Definicao dos tipos de mensagem do protocolo
│   │   └── validators.js        # Validacao de estrutura dos payloads
│   │
│   └── shared/
│       ├── constants.js         # Constantes globais (portas, limites, versao)
│       └── logger.js            # Logger estruturado (com niveis e timestamps)
│
├── test/
│   ├── crypto.test.js           # Testes do modulo criptografico
│   ├── protocol.test.js         # Testes de validacao do protocolo
│   ├── nonce.test.js            # Testes do gerenciador de nonces
│   ├── integration.test.js      # Testes de integracao E2E
│   ├── double-ratchet.test.js   # Testes do Double Ratchet
│   ├── trust-store.test.js      # Testes do TrustStore + SAS
│   ├── message-crypto.test.js   # Testes do MessageCrypto (padding, encrypt)
│   └── state-manager.test.js    # Testes de persistencia de estado
│
├── scripts/
│   └── generate-fingerprint.js  # Utilitario: gera fingerprint de chave publica
│
├── .editorconfig
├── .eslintrc.js
├── .gitignore
├── .npmrc
├── .prettierrc
├── jsconfig.json
├── package.json
└── README.md
```

---

## 4. Responsibility of Each Module

### 4.1 Server

#### `src/server/index.js` — Entry Point
- Initializes the WebSocket server on the configured port (default: 3600)
- Registers connection/disconnection handlers
- Graceful shutdown (SIGINT, SIGTERM)
- Prints local network information (IP, port)

#### `src/server/WebSocketServer.js` — WebSocket Management
- Wrapper over `ws.WebSocketServer`
- Configures limits: `maxPayload` (64KB), heartbeat (ping/pong every 30s)
- Detects disconnected clients via heartbeat
- Emits typed events: `connection`, `message`, `close`, `error`
- Does not interpret content — treats everything as an opaque `Buffer`

#### `src/server/SessionManager.js` — Sessions
- Maintains a map of active sessions: `Map<sessionId, { ws, nickname, publicKey, connectedAt }>`
- Generates session IDs with `crypto.randomUUID()`
- Broadcasts the user list when someone joins/leaves
- Rejects duplicate nicknames
- Inactive session timeout (configurable)
- **Stores the public key only to redistribute it** — it is not a secret, it is an identity

#### `src/server/MessageRouter.js` — Routing
- Receives payloads of type `encrypted_message`
- Validates structure (has `to`, `from`, `payload`)
- **Does not open `payload`** — only checks the routing fields
- Forwards to the recipient's WebSocket
- If the recipient is offline and was recently disconnected, queues it in the OfflineQueue
- Returns an error if the recipient is not found and has no recent history
- Basic rate limiting: max 30 messages/second per client

#### `src/server/OfflineQueue.js` — Offline Queue
- Stores encrypted (opaque) messages for disconnected peers
- Keyed by nickname + publicKey (ensures it only delivers if the peer reconnects with the same key)
- Limits: max 100 msgs/peer, max 1000 total, max 1h of age
- If a peer reconnects with a different key (new client), the queue is discarded
- Periodic cleanup every 5min
- The queue is lost when the server restarts (in-memory)

### 4.2 Client

#### `src/client/index.js` — Entry Point
- Asks the user for a nickname
- Asks for the server's IP:port (default: localhost:3600)
- Initializes the KeyManager (generates a key pair)
- Displays the public key fingerprint for verification
- Connects to the server and starts the UI

#### `src/client/UI.js` — Blessed Interface
- Layout divided into 3 areas:

```
┌─────────────────────────────────────────┐
│  SecureLAN Chat         [3 online]  E2E │  <- Header/Status bar
├─────────────────────────────────────────┤
│                                         │
│  [10:30] Alice: Ola!                    │  <- Chat area (scrollable)
│  [10:31] Voce: Oi Alice!               │
│  [10:32] * Bob entrou no chat           │
│  [10:32] Bob: Fala galera               │
│                                         │
├─────────────────────────────────────────┤
│  > Digite sua mensagem...            │  <- Input box
└─────────────────────────────────────────┘
```

- The status bar shows: chat name, online users, E2E indicator
- Chat area with automatic and manual scroll
- Input with history (up/down arrows)
- Distinct colors per user (chalk)
- Special commands: `/quit`, `/users`, `/fingerprint`, `/clear`, `/file`, `/sound`, `/help`
- Animated "typing..." indicator with support for multiple peers
- Sound notifications (toggle via `/sound on|off`)
- Progress bar for file transfers
- Notifications for users joining/leaving

#### `src/client/Connection.js` — WebSocket Client
- Connects to the server via `ws`
- Automatic reconnect with exponential backoff (1s, 2s, 4s, 8s, max 30s)
- Ping/pong to detect disconnection
- Serializes/deserializes protocol messages (JSON for control, Buffer for encrypted data)
- Emits events to the ChatController

#### `src/client/ChatController.js` — Orchestrator
- Connects: UI <-> Connection <-> Crypto
- Send flow: UI input -> encrypt -> Connection send
- Receive flow: Connection receive -> decrypt -> UI display
- Manages state: peer list, received public keys, derived shared keys
- Performs the handshake with each new peer
- Validates fingerprints
- Manages file transfers via FileTransfer
- Sound notification when text messages are received

#### `src/client/FileTransfer.js` — File Transfer
- Sending: reads the file, splits it into 48KB chunks, encrypts each chunk E2E via broadcast
- Receiving: reassembles chunks, verifies SHA-256, saves to `./downloads/`
- Throttling: max 25 chunks/sec (below the rate limit of 30/sec)
- Timeout: 30s for incomplete transfers
- Support for files up to 50MB

### 4.3 Crypto

#### `src/crypto/KeyManager.js` — Keys
- Generates a Curve25519 pair with `sodium.crypto_box_keypair()`
- Stores it in `sodium.sodium_malloc()` (secure memory, does not go to swap)
- Exports the public key as a `Buffer` (to send to the server)
- Generates a fingerprint: `SHA-256(publicKey)` formatted as `XXXX:XXXX:XXXX:XXXX`
- A `destroy()` method that calls `sodium.sodium_memzero()` on the keys
- **Never** serializes the private key to disk, log, or network

#### `src/crypto/MessageCrypto.js` — Encrypt/Decrypt
- **Encrypt**: `sodium.crypto_box_easy(message, nonce, theirPublicKey, mySecretKey)`
- **Decrypt**: `sodium.crypto_box_open_easy(ciphertext, nonce, theirPublicKey, mySecretKey)`
- The `crypto_box` function internally uses:
  - **X25519**: Diffie-Hellman to derive the shared key
  - **XSalsa20**: Stream cipher for confidentiality
  - **Poly1305**: MAC for authenticity and integrity
- Returns `{ ciphertext: Buffer, nonce: Buffer }`
- Validates the minimum ciphertext size (16-byte MAC)

#### `src/crypto/Handshake.js` — Peer Management
- Registers peers' public keys received via the server
- Validates the public key size (32 bytes, Curve25519)
- Stores public keys in `Map<peerId, publicKey>`
- Exposes access to the local secret key for use in `crypto_box_easy`
- A `removePeer()` method for cleanup on disconnect
- A `destroy()` method to clear all state

#### `src/crypto/DoubleRatchet.js` — PFS (Perfect Forward Secrecy)
- A simplified implementation of the Double Ratchet (Signal-style)
- Each message uses a unique derived key, destroyed after use
- DH ratchet: `crypto_scalarmult` (X25519) to generate a new DH output each turn
- KDF_RK: `BLAKE2b-512(rootKey, dhOutput)` → new rootKey + chainKey
- KDF_CK: `BLAKE2b-256(chainKey, 0x01)` → messageKey; `BLAKE2b-256(chainKey, 0x02)` → nextChainKey
- Encryption: `crypto_secretbox_easy` (symmetric XSalsa20-Poly1305) with the derived messageKey
- Management of skipped keys (out-of-order messages) with a 60s TTL
- Immediate destruction of keys after use (`sodium_memzero`)
- Automatic fallback to static keys when the ratchet is unavailable

#### `src/crypto/TrustStore.js` — TOFU + SAS
- **TOFU (Trust On First Use)**: Persists peers' fingerprints in `.ciphermesh/trusted-peers.json`
- Detects a public key change (possible MITM) — similar to SSH's `known_hosts`
- **SAS (Short Authentication String)**: A 6-digit code for out-of-band verification
  - `BLAKE2b-256(sortedPubKeys || "CipherMesh-SAS-v1")` → first 3 bytes → 6 decimal digits
  - Both sides compute the same value independently
- TrustResult: `NEW_PEER` | `TRUSTED` | `MISMATCH` | `VERIFIED_MISMATCH`
- Authenticated E2E rotation (`autoUpdatePeer`) preserves the verification status
- Rotation via the server (unauthenticated) does NOT update the trust store

#### `src/crypto/StateManager.js` — Encrypted Persistence
- Persists session state in `.ciphermesh/state/session-state.enc.json`
- `deriveKEK(passphrase, salt?)` — Derives a Key Encryption Key with `crypto_pwhash` (Argon2id)
- `saveState(data, kek, salt)` — Encrypts state with `crypto_secretbox_easy`, saves the envelope `{salt, nonce, ciphertext}`
- `loadState(passphrase)` — Re-derives the KEK from the saved salt, decrypts, returns the object or `null`
- `hasState()` / `clearState()` — Checks existence / removes saved state
- Used to preserve ratchets, keys, and peers across reconnections

#### `src/crypto/NonceManager.js` — Nonces
- Generates 24-byte nonces with `sodium.randombytes_buf()`
- Maintains a **monotonically increasing counter** per peer
- Rejects repeated nonces or ones smaller than the last received (anti-replay)
- Nonce structure:

```
[  8 bytes: timestamp ms  |  4 bytes: counter  |  12 bytes: random  ]
         anti-replay            sequencia           unicidade
```

### 4.4 P2P (Alternative Mode)

#### `src/p2p/Discovery.js` — mDNS Discovery
- Publishes the `_ciphermesh._tcp` service via mDNS using `bonjour-service`
- TXT records: `{ nickname, publicKey, version }`
- Automatically searches for peers of the same type on the LAN
- Emits events: `peer-discovered`, `peer-lost`
- Ignores self (same nickname)

#### `src/p2p/PeerServer.js` — Local Server
- `WebSocketServer` listening on a random port (`port: 0`)
- Accepts inbound connections from peers on the LAN
- Emits `connection(ws)` for the controller to process

#### `src/p2p/PeerConnectionManager.js` — Connection Manager
- Manages outbound and inbound WebSocket connections
- **Deduplication**: The lexicographically smaller nickname initiates the connection
  - If `alice < bob`: Alice connects, Bob waits
  - Result: exactly 1 WebSocket between each pair
- P2P handshake: `{ type: "p2p_handshake", nickname, publicKey, version, timestamp }`
- Reconnect with exponential backoff (2s→30s) for outbound connections
- `send(nickname, data)` / `broadcast(data)` — sends to peer(s)

#### `src/p2p/P2PChatController.js` — P2P Orchestrator
- An adaptation of `ChatController` for peer-to-peer mode
- Uses the **nickname as the peer ID** (stable, vs. the ephemeral sessionId in server mode)
- Same crypto: DoubleRatchet, TOFU, SAS, key rotation, secure wipe
- Same commands: `/verify`, `/trust`, `/trustlist`, `/file`, etc.
- Main difference: messages go directly peer-to-peer, without a relay

| Aspect | Server Mode | P2P Mode |
|---------|---------------|----------|
| Connection | Single WS to the server | Direct WS between each pair of peers |
| Discovery | `JOIN_ACK` from the server | mDNS on the LAN |
| Peer ID | sessionId (ephemeral UUID) | nickname (stable) |
| Routing | Via the server (blind relay) | Direct peer-to-peer |
| Offline queue | Yes (the server stores it) | No (peers must be online) |

#### `src/p2p/index.js` — P2P Entry Point
- Prompt: nickname, passphrase (optional, to restore state)
- Initializes `PeerServer` (random port) + `Discovery` (mDNS)
- `PeerConnectionManager` + `P2PChatController` + `UI`
- Shutdown: saves encrypted state if a passphrase is set

### 4.5 Protocol (Server Mode)

#### `src/protocol/messages.js` — Message Types

Defines the protocol's message types. All messages have:
```js
{
  type: string,       // tipo da mensagem
  version: 1,         // versao do protocolo
  timestamp: number   // Date.now() do remetente
}
```

Types:
| Type | Direction | Description |
|------|---------|-----------|
| `join` | Client -> Server | The client wants to join (nickname + publicKey) |
| `join_ack` | Server -> Client | The server confirms the join (sessionId + peer list) |
| `peer_joined` | Server -> Clients | A new peer joined (nickname + publicKey) |
| `peer_left` | Server -> Clients | A peer left |
| `key_exchange` | Client -> Server -> Client | Public key exchange between peers |
| `encrypted_message` | Client -> Server -> Client | Encrypted message |
| `error` | Server -> Client | Error (duplicate nickname, etc.) |
| `ping` / `pong` | Bidirectional | Heartbeat |

#### `src/protocol/validators.js` — Validation
- Validates the JSON structure of each message type
- Checks required fields and types
- Checks maximum sizes (nickname: 20 chars, payload: 64KB)
- Sanitizes inputs (trim, removal of control characters)
- Rejects messages with an incompatible `version`

### 4.6 Shared

#### `src/shared/constants.js` — Constants

```js
export const SERVER_PORT = 3600;
export const MAX_NICKNAME_LENGTH = 20;
export const MAX_PAYLOAD_SIZE = 65536;          // 64KB
export const HEARTBEAT_INTERVAL_MS = 30000;     // 30s
export const RECONNECT_BASE_MS = 1000;          // 1s
export const RECONNECT_MAX_MS = 30000;          // 30s
export const RATE_LIMIT_PER_SECOND = 30;
export const SESSION_TIMEOUT_MS = 300000;       // 5min inativo
export const PROTOCOL_VERSION = 1;
export const NONCE_SIZE = 24;                   // libsodium nonce
export const PUBLIC_KEY_SIZE = 32;              // Curve25519
export const SECRET_KEY_SIZE = 32;
export const MAC_SIZE = 16;                     // Poly1305

// Offline queue
export const OFFLINE_QUEUE_MAX_PER_PEER = 100;
export const OFFLINE_QUEUE_MAX_AGE_MS = 3600000; // 1h
export const OFFLINE_QUEUE_MAX_TOTAL = 1000;

// File transfer
export const MAX_FILE_SIZE = 50 * 1024 * 1024;  // 50MB
export const FILE_CHUNK_SIZE = 49152;            // 48KB
```

#### `src/shared/logger.js` — Logger
- Levels: `debug`, `info`, `warn`, `error`
- Format: `[HH:MM:SS] [LEVEL] [module] message`
- Level configurable via the `LOG_LEVEL` environment variable
- Never logs message content or private keys
- Logs only metadata: connections, disconnections, errors

---

## 5. Data Model and Payloads

### 5.1 Join Message (client -> server)

```json
{
  "type": "join",
  "version": 1,
  "timestamp": 1739800000000,
  "nickname": "Alice",
  "publicKey": "base64(32 bytes da chave publica Curve25519)"
}
```

### 5.2 Join ACK (server -> client)

```json
{
  "type": "join_ack",
  "version": 1,
  "timestamp": 1739800000050,
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "peers": [
    {
      "sessionId": "660e8400-e29b-41d4-a716-446655440001",
      "nickname": "Bob",
      "publicKey": "base64(chave publica do Bob)"
    }
  ]
}
```

### 5.3 Encrypted Message (client -> server -> client)

```json
{
  "type": "encrypted_message",
  "version": 1,
  "timestamp": 1739800001000,
  "from": "550e8400-e29b-41d4-a716-446655440000",
  "to": "660e8400-e29b-41d4-a716-446655440001",
  "payload": {
    "ciphertext": "base64(mensagem cifrada com crypto_box_easy)",
    "nonce": "base64(24 bytes do nonce usado)"
  }
}
```

**Note**: The `payload` field is completely opaque to the server. It only reads `from` and `to` for routing.

### 5.4 Decrypted content (never travels in cleartext)

After decrypting `payload.ciphertext`, the result is:

```json
{
  "text": "Ola Bob, tudo bem?",
  "sentAt": 1739800001000,
  "messageId": "a1b2c3d4"
}
```

- `sentAt` inside the encrypted payload lets the receiver validate against the external `timestamp`
- `messageId` is a short random ID for reference (not a UUID, just 4 bytes of hex)

#### Encrypted commands (actions)

Besides text messages, the encrypted payload may contain commands (the `action` field):

```json
{ "action": "clear", "sentAt": 1739800001000 }
```

```json
{ "action": "typing", "sentAt": 1739800001000 }
```

- `clear` — clears the chat for all peers
- `typing` — indicates that the sender is typing (2s debounce, expires after 3s at the receiver)
- `file_offer` — offers to send a file (transferId, fileName, fileSize, totalChunks, sha256)
- `file_chunk` — sends a file chunk (transferId, chunkIndex, base64 data)
- `file_complete` — signals the end of the transfer (transferId)

### 5.5 Peer Notification (server -> clients)

```json
{
  "type": "peer_joined",
  "version": 1,
  "timestamp": 1739800002000,
  "peer": {
    "sessionId": "770e8400-e29b-41d4-a716-446655440002",
    "nickname": "Charlie",
    "publicKey": "base64(chave publica do Charlie)"
  }
}
```

### 5.6 Error (server -> client)

```json
{
  "type": "error",
  "version": 1,
  "timestamp": 1739800003000,
  "code": "NICKNAME_TAKEN",
  "message": "O nickname 'Alice' ja esta em uso"
}
```

Error codes:
| Code | Description |
|--------|-----------|
| `NICKNAME_TAKEN` | Nickname already in use |
| `INVALID_MESSAGE` | Invalid message structure |
| `PEER_NOT_FOUND` | The recipient is not online |
| `RATE_LIMITED` | Too many messages per second |
| `PAYLOAD_TOO_LARGE` | Payload exceeds 64KB |

---

## 6. Detailed Cryptographic Flow

### 6.1 Algorithms Used

| Operation | Algorithm | Size | Description |
|----------|-----------|---------|-----------|
| Key pair | **Curve25519** | 32 bytes each | Elliptic curve for key exchange |
| Key exchange | **X25519** (ECDH) | 32-byte result | Diffie-Hellman over Curve25519 |
| Cipher | **XSalsa20** | stream cipher | A variant of Salsa20 with a 24-byte nonce |
| MAC | **Poly1305** | 16-byte tag | Message Authentication Code |
| Nonce | random + counter | 24 bytes | Number used only once |

### 6.2 Why Curve25519 + XSalsa20-Poly1305?

This combination (known as **NaCl crypto_box**) was chosen because:

1. **Modern curve**: Curve25519 was designed by Daniel J. Bernstein to be resistant to timing attacks and to have secure implementations
2. **Authenticated encryption**: XSalsa20-Poly1305 combines confidentiality + integrity in a single atomic operation (AEAD)
3. **24-byte nonce**: Large enough to be generated randomly with no practical risk of collision (2^192 combinations)
4. **No padding oracle**: A stream cipher needs no padding, eliminating an entire class of attacks
5. **Misuse-resistant**: Hard to use incorrectly (compared to AES-CBC, manual AES-CTR, etc.)

### 6.3 Key Generation

```
1. Cliente inicia
2. sodium.crypto_box_keypair() gera:
   - publicKey:  32 bytes (pode ser compartilhada)
   - secretKey:  32 bytes (NUNCA sai da memoria do processo)
3. Ambas armazenadas em sodium.sodium_malloc() (secure memory)
4. Fingerprint = SHA256(publicKey) formatada como XXXX:XXXX:XXXX:XXXX
```

### 6.4 Authenticated Encryption with crypto_box_easy

`crypto_box_easy` does everything internally in a single atomic operation:

```
crypto_box_easy(ciphertext, plaintext, nonce, recipientPublicKey, senderSecretKey)

Internamente:
1. X25519 DH:    sharedSecret = ECDH(recipientPub, senderSec)
2. Key derivation: encKey = HSalsa20(sharedSecret, zeros)
3. Cifra:        XSalsa20(plaintext, nonce, encKey) -> ciphertext
4. MAC:          Poly1305(ciphertext) -> tag de 16 bytes
5. Output:       tag || ciphertext (autenticado)
```

The shared key is derived implicitly on each call. The DH guarantees
that both sides (Alice and Bob) arrive at the same secret without exchanging it over the network.

### 6.5 Message Encryption

```
Input:
  - plaintext:           Buffer (mensagem em UTF-8)
  - nonce:               24 bytes (gerado pelo NonceManager)
  - recipientPublicKey:  32 bytes (chave publica do destinatario)
  - senderSecretKey:     32 bytes (chave secreta do remetente)

Processo:
  ciphertext = crypto_box_easy(plaintext, nonce, recipientPublicKey, senderSecretKey)

Output:
  - ciphertext: Buffer (plaintext.length + 16 bytes de MAC)
  - nonce:      24 bytes (enviado junto, nao e segredo)

Total enviado: ciphertext (N+16 bytes) + nonce (24 bytes)
```

### 6.6 Message Decryption

```
Input:
  - ciphertext:          Buffer (recebido da rede)
  - nonce:               24 bytes (recebido da rede)
  - senderPublicKey:     32 bytes (chave publica do remetente)
  - recipientSecretKey:  32 bytes (chave secreta do destinatario)

Processo:
  1. NonceManager valida que nonce nao foi usado antes (anti-replay)
  2. plaintext = crypto_box_open_easy(ciphertext, nonce, senderPublicKey, recipientSecretKey)
  3. Se MAC invalido -> rejeita (mensagem foi adulterada)
  4. Se MAC valido -> parse do JSON interno

Output:
  - plaintext: Buffer (mensagem original)
```

### 6.7 Nonce Structure (24 bytes)

```
┌──────────────────┬──────────────┬──────────────────────┐
│  Timestamp (8B)  │ Counter (4B) │    Random (12B)      │
│  ms desde epoch  │ sequencial   │  sodium.randombytes  │
└──────────────────┴──────────────┴──────────────────────┘

- Timestamp: impede replay entre sessoes diferentes
- Counter: garante ordenacao e unicidade dentro da sessao
- Random: garante unicidade mesmo com clocks sincronizados
```

### 6.8 Fingerprint Verification

The fingerprint lets users verify each other's identity **out of band** (for example, in person or by phone):

```
1. Alice ve seu fingerprint: A1B2:C3D4:E5F6:7890
2. Bob ve o fingerprint de Alice: A1B2:C3D4:E5F6:7890
3. Bob confirma pessoalmente com Alice que os valores batem
4. Se nao baterem -> MITM detectado
```

The fingerprint is computed like this:
```
fingerprint = SHA-256(publicKey)
            = primeiros 8 bytes, formatados em hex com separador ':'
            = "A1B2:C3D4:E5F6:7890"
```

---

## 7. Handshake Protocol

### 7.1 Full Diagram

```
  Cliente A                    Servidor                    Cliente B
     │                            │                            │
     │  1. JOIN(nick, pubKeyA)    │                            │
     │ ──────────────────────────>│                            │
     │                            │                            │
     │  2. JOIN_ACK(sessionId,    │                            │
     │     peers=[B: pubKeyB])    │                            │
     │ <──────────────────────────│                            │
     │                            │                            │
     │                            │  3. PEER_JOINED(A, pubKeyA)│
     │                            │───────────────────────────>│
     │                            │                            │
     │  4. Deriva sharedKey(A,B)  │     5. Deriva sharedKey(B,A)
     │  usando pubKeyB + secKeyA  │     usando pubKeyA + secKeyB
     │                            │                            │
     │  6. ENCRYPTED_MSG ─────────│────────────────────────>   │
     │                            │    7. Decifra com sharedKey│
     │                            │                            │
```

### 7.2 Detailed Steps

**Step 1 — JOIN**: Client A generates a key pair and sends `{ type: "join", nickname: "Alice", publicKey: base64(pubKeyA) }` to the server.

**Step 2 — JOIN_ACK**: The server validates the nickname (unique?), registers the session, and returns the list of already-connected peers with their public keys.

**Step 3 — PEER_JOINED**: The server notifies all existing clients that Alice joined, including her public key.

**Steps 4 and 5 — Derivation**: Each side computes `crypto_box_beforenm()` with the other's public key and its own private key. Result: the same shared key.

**Step 6 — Encrypted message**: Alice encrypts and sends. The server relays without reading.

**Step 7 — Decryption**: Bob decrypts with the derived shared key.

### 7.3 Handshake Security

- The public key travels in cleartext (this is safe — it is public by definition)
- The private key **never** leaves the client's process
- The server sees public keys but cannot derive the shared key (it would need a private key)
- An attacker who captures all traffic sees only public keys + encrypted payloads = useless without a private key

**PFS implemented**: The system uses a simplified Double Ratchet for live conversations. Each message uses a unique derived key, destroyed after use. Compromising one key reveals at most ONE message. Offline messages use static keys as a fallback.

---

## 8. Step-by-Step Communication Flow

### 8.1 Full Scenario: Alice sends "Ola" to Bob

```
TEMPO  ACAO
─────  ──────────────────────────────────────────────────────
t0     Alice digita "Ola" no input e pressiona Enter

t1     ChatController recebe o texto da UI
       ChatController verifica se tem sharedKey com Bob
       Se nao tem -> erro "Handshake nao completado com Bob"

t2     MessageCrypto.encrypt():
       - NonceManager gera nonce de 24 bytes
       - Serializa payload interno: { text: "Ola", sentAt: t2, messageId: "a1b2" }
       - crypto_box_easy_afternm(payload, nonce, sharedKeyAB)
       - Retorna { ciphertext: Buffer, nonce: Buffer }

t3     Connection envia ao servidor:
       {
         type: "encrypted_message",
         from: "alice-session-id",
         to: "bob-session-id",
         payload: { ciphertext: "base64(...)", nonce: "base64(...)" }
       }

t4     Servidor (MessageRouter):
       - Valida estrutura (tem type, from, to, payload)
       - NAO abre payload
       - Encontra WebSocket do Bob pelo sessionId
       - Encaminha o JSON inteiro para Bob

t5     Bob (Connection) recebe o JSON
       ChatController identifica: encrypted_message de Alice

t6     MessageCrypto.decrypt():
       - Extrai ciphertext e nonce do payload
       - NonceManager valida nonce (nao repetido, counter valido)
       - crypto_box_open_easy_afternm(ciphertext, nonce, sharedKeyAB)
       - Se MAC falhar -> rejeita (mensagem corrompida/adulterada)
       - Se MAC ok -> parse do JSON interno

t7     ChatController recebe { text: "Ola", sentAt: t2, messageId: "a1b2" }
       Valida que sentAt e razoavel (nao muito no passado/futuro)

t8     UI.displayMessage("Alice", "Ola", timestamp)
       Bob ve: [10:30] Alice: Ola
```

### 8.2 Scenario: Group Chat (broadcast)

To send to everyone, Alice encrypts **individually** for each peer:

```
Alice -> Bob:     encrypt(msg, nonceAB, sharedKeyAB)
Alice -> Charlie: encrypt(msg, nonceAC, sharedKeyAC)
```

Each message has a different nonce and ciphertext because each shared key is different. The server receives N messages and routes each one to the correct recipient.

**Impact**: O(N) encryptions per group message. Acceptable for a LAN with few users.

**Sender keys (real groups) — `src/crypto/SenderKey.js`**: an O(1) alternative. Each
sender has a *sender key chain* (symmetric BLAKE2b ratchet) per room; the
message is encrypted **once** (`crypto_secretbox` + length padding) and the
**same** ciphertext is valid for all members. The chain is distributed once to
each member over the pairwise channel (never in cleartext). Forward secrecy: the chain
advances with each message and is rotated (`rotate()`) on member changes (with
redistribution). It supports out-of-order delivery (skipped keys, limited to
`maxSkip`) and rejects replay (an already-consumed counter) and tampering (Poly1305 MAC).

**Live integration (P2P)**: normal room messages use sender keys — encrypted
once (`p2p_group`) and sent identically to all peers in the room. The sender key
is distributed (`sk_dist`) over the pairwise channel when joining the room / when a peer
joins my room; since it goes over the same TCP connection, it arrives ordered before
any group message. When a peer leaves the room, my sender key is
rotated and redistributed (forward secrecy). Deniable, ephemeral, DMs,
store-and-forward, and cover-constant remain on the pairwise path because they have their own
semantics. (On the relay, the same model would give O(1) multicast; it requires
a server change and is not wired up there yet.)

---

## 9. Initialization Strategy

### 9.1 Server

```
1. Carregar constantes (constants.js)
2. Criar instancia WebSocketServer na porta configurada
3. Criar SessionManager (mapa vazio de sessoes)
4. Criar MessageRouter (referencia ao SessionManager)
5. Registrar handlers:
   - on('connection') -> SessionManager.handleConnection()
   - on('close')      -> SessionManager.handleDisconnection()
   - on('message')    -> MessageRouter.route()
6. Iniciar heartbeat interval (ping todos os clientes a cada 30s)
7. Registrar SIGINT/SIGTERM para graceful shutdown:
   - Notificar todos os clientes
   - Fechar conexoes
   - Limpar recursos
8. Imprimir no console:
   - IP local (todas as interfaces de rede)
   - Porta
   - "Servidor pronto. Clientes podem conectar em ws://<IP>:3600"
```

### 9.2 Client

```
 1. Exibir banner "SecureLAN Chat v1.0"
 2. Pedir nickname (validar: 1-20 chars, alfanumerico + underscore)
 3. Pedir endereco do servidor (default: localhost:3600)
 4. Gerar par de chaves (KeyManager)
 5. Exibir fingerprint da chave publica
 6. Conectar ao servidor via WebSocket
 7. Enviar mensagem JOIN (nickname + publicKey)
 8. Aguardar JOIN_ACK
 9. Se erro (nickname duplicado) -> pedir outro nickname
10. Receber lista de peers e derivar sharedKey com cada um
11. Inicializar UI blessed
12. Exibir lista de usuarios online
13. Entrar no loop de input
14. Registrar handler de SIGINT para:
    - sodium_memzero() em todas as chaves
    - Fechar conexao WebSocket
    - Destruir UI blessed
```

---

## 10. Security — Threat Analysis

### 10.1 Threat Model

| Threat | Mitigation | Status |
|--------|-----------|--------|
| **Malicious server reads messages** | Impossible — the server has no private key | Mitigated |
| **Server alters messages** | The Poly1305 MAC detects tampering | Mitigated |
| **Message replay** | Nonce with timestamp + monotonically increasing counter | Mitigated |
| **Man-in-the-Middle (MITM)** | TOFU + SAS (6-digit code) + fingerprint | Mitigated |
| **Private key leak** | Secure memory (sodium_malloc + mlock) | Mitigated |
| **Plaintext in memory** | Secure wipe (sodium_memzero) after use | Mitigated |
| **Private key in swap** | sodium_malloc() with mlock | Mitigated |
| **Brute force on the key** | Curve25519 = 128 bits of security (~3x10^38 operations) | Infeasible |
| **Nonce reuse** | Hybrid nonce (timestamp + counter + random) | Mitigated |
| **Denial of Service** | Rate limiting + maxPayload | Partial |
| **Forward secrecy** | Double Ratchet — a unique key per message | Mitigated |
| **Metadata analysis** | Message padding + fixed sizes | Partial |

### 10.2 What the server CAN deduce (metadata)

Even without reading content, the server knows:
- **Who** is online
- **Who** talks to whom
- **When** messages are sent — *mitigated by cover traffic (optional)*
- **Approximate size** of messages — *mitigated: only the padding bucket leaks*
- **Frequency** of communication — *mitigated by cover traffic (optional)*

Implemented mitigations:
- **Length padding** (`MessageCrypto.padMessage`, buckets
  `[128..32768]`): applied on all three encryption paths (static, ratchet, and
  deniable) before encrypting. The server sees only which bucket, not the real size.
- **File chunk padding** (`FileTransfer`): the last (partial) chunk is
  padded up to the full size with random bytes, so all chunks have the
  same size on the wire; the receiver truncates it back using `fileSize`. This hides
  the exact file size (only the chunk-rounded size leaks).
- **Cover traffic** (`/cover`, `src/shared/coverTraffic.js`): encrypted
  decoy messages (`action: 'cover'`) with random filler, indistinguishable from
  real messages; the recipient discards them silently. Two modes:
  - `on` (jitter): decoys at random intervals (20-60s) — a baseline of noise.
  - `constant`: a fixed-rate channel (~3s) — each slot carries a queued real
    message or, if there is none, a decoy. The wire keeps an identical cadence
    whether you are chatting or idle (cost: up to ~3s of latency per message).
  This masks *when/how often* you chat, not *with whom*.
- **Migrating to P2P** eliminates the central server (but exposes IPs on the LAN).

- **Sealed sender** (`src/crypto/SealedSender.js`): removes the `from` from the
  network envelope. The sender's identity goes inside a libsodium *sealed box*
  (`crypto_box_seal` — anonymous encryption with an ephemeral key to the recipient's
  public key), which only the recipient opens. The relay routes only by `to` and does not
  see who sent it. The primitive is implemented and tested; wiring it into the envelope
  (client seals / server routes without `from` / recipient opens and decrypts the
  inner content) is the next step.

Still leaking: who is online and who *receives* (the `to`, inherent to star
routing). With sealed sender, the *sender* side of the social graph stays hidden.

### 10.3 Resistance to Known Attacks

| Attack | Resistant? | Explanation |
|--------|-------------|-----------|
| Padding oracle | Yes | XSalsa20 is a stream cipher, no padding |
| Timing attack | Yes | libsodium uses constant-time comparisons |
| Chosen ciphertext | Yes | Poly1305 authenticates before decrypting |
| Key confusion | Yes | crypto_box uses typed keys (pub/sec) |
| Nonce misuse | Partial | The hybrid nonce reduces risk, but XSalsa20 is not nonce-misuse-resistant (unlike AES-GCM-SIV) |

---

## 11. Future Improvements

### 11.1 Perfect Forward Secrecy (PFS) — IMPLEMENTED

**Implementation**: A simplified Double Ratchet using libsodium primitives.

**Hybrid model**:
- **Ratchet** for live conversations (both peers online) — each message uses a unique key
- **Static keys** (`crypto_box`) as a fallback for the offline queue and initial msgs

**Primitives used**:
- `crypto_scalarmult` — raw X25519 DH for ratchet steps
- `crypto_generichash` (BLAKE2b) — KDF to derive root keys and chain keys
- `crypto_secretbox_easy` — Symmetric encryption with a per-message derived key
- `sodium_malloc` / `sodium_memzero` — Secure memory, immediate destruction of keys

**Files**:
- `src/crypto/DoubleRatchet.js` — The ratchet's main class (KDF_RK, KDF_CK, encrypt, decrypt, skipped keys)
- Integrated into `Handshake.js` (per-peer ratchet management) and `ChatController.js` (wiring)

**Wire format**: Ratcheted msgs include `ephemeralPublicKey`, `counter`, `previousCounter` in the payload. Static msgs have no `ephemeralPublicKey`. The server is unaffected (opaque relay).

**Anti-replay**: The ratchet uses its own counter (no NonceManager needed). Static msgs continue to use the NonceManager.

### 11.2 TOFU + SAS (Identity Verification) — IMPLEMENTED

**TOFU (Trust On First Use)**: When connecting with a peer for the first time, the public key fingerprint is saved locally in `.ciphermesh/trusted-peers.json`. On subsequent connections, if the key changes, the user is alerted (similar to SSH's `known_hosts`).

**SAS (Short Authentication String)**: A 6-digit code that both sides compute independently. It enables out-of-band verification (by voice, in person) to confirm there is no MITM.

**Commands**:
- `/verify <nick>` — Shows the 6-digit SAS code
- `/verify-confirm <nick>` — Marks a peer as verified after confirming the SAS
- `/trust <nick>` — Accepts a peer's new key (resets verification)
- `/trustlist` — Trust status of all online peers

**Trust model for key rotation**:
- Authenticated E2E rotation (via the encrypted channel, action `key_rotation`) → `autoUpdatePeer()` preserves the `verified` status
- Rotation via the server (`PEER_KEY_UPDATED`) → does NOT update the trust store (unauthenticated, potential MITM)

### 11.3 Secure Memory Wipe — IMPLEMENTED

**Problem**: After decrypting, the plaintext remained in a normal `Buffer.alloc()`, subject to swap and GC.

**Solution**:
- `unpadSecure(padded)`: Copies the plaintext to `sodium_malloc()`, wipes the original padded buffer
- `encrypt()` in MessageCrypto and DoubleRatchet: `sodium_memzero(padded)` after encryption
- `decrypt()` in DoubleRatchet: `sodium_memzero(padded)` in case of an invalid MAC
- `ChatController.#onEncryptedMessage`: `finally { sodium_memzero(plaintext) }` after processing

**Limitation**: JS strings (`toString('utf-8')`, `JSON.parse()`) CANNOT be wiped — the V8 GC controls their lifetime. Only data in a `Buffer` is wiped.

### 11.4 Reconnect with State — IMPLEMENTED

**Problem**: On disconnecting and reconnecting, the ratchets and keys were lost, forcing renegotiation.

**Solution**: `StateManager` persists encrypted state with the user's passphrase.

**Flow**:
```
Startup:
  1. Se existe estado salvo → prompt passphrase → loadState() → restaura KeyManager, Handshake, peers
  2. Se nao existe → prompt passphrase opcional (para proteger sessao futura)

Shutdown (Ctrl+C, /quit):
  Se passphrase definida → serializeState() → saveState() cifrado
```

**State encryption**:
- KDF: `crypto_pwhash` (Argon2id) with ops=3, mem=256MB → 32-byte KEK
- Cipher: `crypto_secretbox_easy` (symmetric XSalsa20-Poly1305) with the KEK
- Envelope: `{ salt, nonce, ciphertext }` in JSON

**Serialization**:
- `DoubleRatchet.serialize()` / `deserialize()` — all private fields in base64, secrets in `sodium_malloc`
- `KeyManager.serialize()` / `deserialize()` — publicKey + secretKey
- `Handshake.serializeState()` / `restoreState()` — ratchets + peerKeys + mySessionId
- `Handshake.migrateRatchet(oldId, newId)` — re-maps the ratchet when the sessionId changes on reconnect

### 11.5 P2P with mDNS — IMPLEMENTED

**Alternative mode** (`npm run p2p`) that eliminates the central server using discovery via mDNS on the LAN.

**Architecture**:
```
                    LAN (mDNS)
         ┌────── _ciphermesh._tcp ──────┐
         │                              │
   ┌─────┴─────┐                 ┌─────┴─────┐
   │  Peer A   │◄──── WS ──────►│  Peer B   │
   │ PeerServer│    direto       │ PeerServer│
   │ :random   │                 │ :random   │
   └───────────┘                 └───────────┘
```

**Components**:
- `Discovery.js` — publishes/searches the `_ciphermesh._tcp` service via `bonjour-service` (pure JS, Windows-compatible)
- `PeerServer.js` — WebSocket server on a random port for inbound connections
- `PeerConnectionManager.js` — manages all connections + deduplication
- `P2PChatController.js` — same crypto (DoubleRatchet, TOFU, SAS, key rotation)

**Connection deduplication**: When Alice and Bob discover each other simultaneously via mDNS, the peer with the lexicographically smaller nickname initiates. Result: exactly 1 WebSocket between each pair.

**P2P protocol**:
- `p2p_handshake`: `{ type, nickname, publicKey, version, timestamp }` — exchanged when the WebSocket opens
- `p2p_message`: `{ type, payload: { ciphertext, nonce, ephemeralPublicKey?, counter?, previousCounter? } }` — the same encrypted format

**Future evolution** — P2P with a DHT (for larger networks):
```
1. Distributed Hash Table para discovery
2. Cada no mantem tabela de roteamento parcial
3. Mensagens podem ser roteadas por multiplos hops
4. Redundancia e tolerancia a falhas
```

### 11.6 Professional Open-Source Project

**Repository structure**:
```
securelan-chat/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml              # CI: lint + test em cada PR
│   │   ├── release.yml         # Release automatica com tags
│   │   └── security-audit.yml  # npm audit semanal
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── CODEOWNERS
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md             # Politica de seguranca
│   ├── CONTRIBUTING.md         # Guia de contribuicao
│   └── PROTOCOL.md             # Especificacao do protocolo
├── LICENSE                     # MIT ou Apache-2.0
├── CHANGELOG.md                # Historico de mudancas (semver)
├── CODE_OF_CONDUCT.md
└── SECURITY.md                 # Como reportar vulnerabilidades
```

**Best practices**:
- Semantic versioning (semver)
- Conventional commits
- CI/CD with GitHub Actions
- Dependabot to update dependencies
- CodeQL for static security analysis
- Releases signed with GPG
- Documentation on GitHub Pages
- Badges in the README (CI, coverage, license, version)
- Issue templates and PR templates
- Security policy with a responsible-disclosure process

### 11.7 Other Improvements

| Improvement | Priority | Complexity |
|----------|------------|-------------|
| Group messages with a group key | High | Medium |
| ~~Encrypted file transfer~~ | ~~Medium~~ | ~~Medium~~ | ✅ Implemented |
| ~~"Typing..." indicator~~ | ~~Low~~ | ~~Low~~ | ✅ Implemented |
| ~~Sound notifications~~ | ~~Low~~ | ~~Low~~ | ✅ Implemented |
| ~~Offline messages (server-side queue)~~ | ~~Medium~~ | ~~High~~ | ✅ Implemented |
| Multiple devices per user | Low | High |
| ~~Automatic key rotation~~ | ~~High~~ | ~~Medium~~ | ✅ Implemented |
| ~~Message padding (anti-metadata)~~ | ~~Medium~~ | ~~Low~~ | ✅ Implemented |
| ~~TLS on the WebSocket (wss://)~~ | ~~Medium~~ | ~~Low~~ | ✅ Implemented |
| Server authentication (certificate) | Medium | Medium |
| ~~Reconnect with encrypted state~~ | ~~High~~ | ~~High~~ | ✅ Implemented |
| ~~P2P with mDNS (alternative mode)~~ | ~~Medium~~ | ~~High~~ | ✅ Implemented |

---

## 12. Glossary

| Term | Definition |
|-------|-----------|
| **E2EE** | End-to-End Encryption. Encryption where only the endpoints (sender and recipient) can read the content. Intermediaries (servers) have no access. |
| **Curve25519** | An elliptic curve designed by Daniel J. Bernstein. Offers 128 bits of security with 32-byte keys. The basis of X25519 (key exchange). |
| **X25519** | A key-exchange protocol (Diffie-Hellman) based on Curve25519. Two parties with different keys arrive at a shared secret. |
| **XSalsa20** | A stream cipher. A variant of Salsa20 with an extended 24-byte nonce (vs. 8 in the original Salsa20). Designed by DJB. |
| **Poly1305** | A Message Authentication Code (MAC). Generates a 16-byte tag proving the message was not altered. Combined with XSalsa20, it forms `crypto_box`. |
| **AEAD** | Authenticated Encryption with Associated Data. A cipher that simultaneously guarantees confidentiality (nobody reads) and integrity (nobody alters). |
| **Nonce** | Number Used Once. A unique value used in each encryption operation. If reused with the same key, security is compromised. |
| **PFS** | Perfect Forward Secrecy. A property where the compromise of long-term keys does not affect past sessions. |
| **DH** | Diffie-Hellman. A protocol that lets two parties establish a shared secret over an insecure channel. |
| **MAC** | Message Authentication Code. A function that produces a verifiable tag guaranteeing a message's integrity and authenticity. |
| **Fingerprint** | A short hash of a public key, used for human verification of identity. |
| **Relay** | A server that forwards data without interpreting the content. |
| **Handshake** | The process of establishing a secure connection between two parties, including key exchange and identity verification. |
| **Side-channel attack** | An attack that exploits information leaked by the implementation (execution time, power consumption, cache) instead of attacking the algorithm mathematically. |
| **sodium_malloc** | A libsodium function that allocates protected memory: does not go to swap, is zeroed when freed, and is protected against reads by other processes. |
| **Double Ratchet** | An algorithm used by Signal that combines a DH ratchet with a KDF chain to guarantee per-message PFS. |
| **TOFU** | Trust On First Use. A trust model where a peer's public key is accepted on the first connection and saved locally. Later changes trigger alerts (similar to SSH known_hosts). |
| **SAS** | Short Authentication String. A short code (6 digits) derived from both sides' public keys, used for out-of-band identity verification. |
| **BLAKE2b** | A fast and secure cryptographic hash function. Used as the KDF in the Double Ratchet and to compute the SAS. Supports keyed hashing (MAC). |
| **mDNS** | Multicast DNS. A protocol for name resolution on local networks without a central DNS server. Used for service discovery (like Apple's Bonjour). |
