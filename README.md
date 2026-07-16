<div align="center">

```
 ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ ███╗   ███╗███████╗███████╗██╗  ██╗
██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗████╗ ████║██╔════╝██╔════╝██║  ██║
██║     ██║██████╔╝███████║█████╗  ██████╔╝██╔████╔██║█████╗  ███████╗███████║
██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║
╚██████╗██║██║     ██║  ██║███████╗██║  ██║██║ ╚═╝ ██║███████╗███████║██║  ██║
 ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
```

### End-to-end encrypted terminal chat — the server can't read a single word.

[![CI](https://github.com/FelipeKreulich/secret-chat-lan/actions/workflows/ci.yml/badge.svg)](https://github.com/FelipeKreulich/secret-chat-lan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A5%2020-brightgreen)](package.json)
[![Crypto](https://img.shields.io/badge/E2EE-libsodium-7b2dff)](docs/ARCHITECTURE.md)

**[🇧🇷 Leia em Português](README.pt-BR.md)** · [Setup Guide](docs/SETUP.md) · [Architecture](docs/ARCHITECTURE.md) · [Security Policy](SECURITY.md)

</div>

---

```
 You  ──[encrypted payload]──▶  Relay (blind)  ──[encrypted payload]──▶  Friend
        Curve25519 + XSalsa20-Poly1305 · Double Ratchet · zero-knowledge
```

CipherMesh is a terminal chat where **encryption is the product**. Keys live in
locked memory pages, every message gets a fresh ratchet key, and the relay
server only ever sees ciphertext — it can't read, alter, or fake anything.
Works on your LAN out of the box, and across the internet with
[Tailscale](docs/SETUP.md#conectando-pela-internet-tailscale) (no port
forwarding, survives CGNAT).

## ✨ Highlights

|     | Feature | The gist |
|-----|---------|----------|
| 🔐 | **Real E2EE** | Curve25519 + XSalsa20-Poly1305 via libsodium, keys in `sodium_malloc` — never touch disk |
| 🔄 | **Perfect Forward Secrecy** | Double Ratchet: one key per message, compromise today ≠ read yesterday |
| 🕶️ | **Metadata resistance** | Fixed-bucket length padding on every ciphertext + opt-in cover traffic (`/cover`) to blur when you chat |
| 🕵️ | **TOFU + SAS** | Key-change detection (MITM alarm) and 6-digit voice-verifiable codes |
| 🌐 | **LAN & internet** | Auto-detects Tailscale, shows the reachable address in the banner |
| 📨 | **Invites with QR** | `/invite` prints a `ciphermesh://` string + QR — paste it, you're in the right room |
| ✓✓ | **Encrypted read receipts** | The ✓✓ travels as ordinary ciphertext — the server can't tell it apart |
| 🗂️ | **Encrypted local history** | Opt-in (passphrase only), Argon2id + XSalsa20-Poly1305, `/search` & `/export` |
| 🖼️ | **Image previews** | Received photos render right in the chat as colored half-blocks |
| 📎 | **Resumable transfers** | Lost chunks are re-requested; reconnects resume from where they stopped |
| 💬 | **Modern chat feel** | Right-aligned own messages, per-user emoji avatars, replies with quotes, `:fire:` → 🔥 |
| 🎞️ | **Animated UI** | Splash intro, reconnect spinner, live transfer bars (shimmer + ETA), a lock-closing handshake on connect, and a pulsing "new messages ↓" pill |
| 👻 | **Deniable & ephemeral** | Symmetric-crypto deniable mode; ephemeral messages *burn away* char-by-char when they expire |
| 🛰️ | **Serverless P2P mode** | mDNS peer discovery on the LAN — no relay at all |

## 🚀 Quick start

```bash
git clone https://github.com/FelipeKreulich/secret-chat-lan.git
cd secret-chat-lan
npm install
```

**Host** (one machine runs the relay):

```bash
npm run server          # or: docker compose up -d
```

**Everyone** (including the host):

```bash
npm run client          # nickname → passphrase (optional) → server address
```

On the same network, use the LAN IP from the server banner (`192.168.x.x:3600`).
Across the internet, install [Tailscale](https://tailscale.com) on both sides
and use the `Internet` address from the banner — full walkthrough in
[docs/SETUP.md](docs/SETUP.md).

Already in the chat? Run `/invite <your-ip>:3600` and send the string (or the
QR code) to whoever you want to pull in.

**No server at all?** `npm run p2p` — peers find each other via mDNS.

## 💬 Commands

<details>
<summary><b>Essentials</b></summary>

| Command | Description |
|---------|-------------|
| `/help` | All commands |
| `/users` | Who's online (with away/status) |
| `/msg <nick> <text>` | Private message (DM) |
| `/reply <text>` | Reply quoting the last received message |
| `/invite [host:port]` | Generate a `ciphermesh://` invite + QR code |
| `/nick <new>` | Change nickname (before joining — recovers from "nickname taken") |
| `/quit` | Leave |

</details>

<details>
<summary><b>Rooms</b></summary>

| Command | Description |
|---------|-------------|
| `/join <room>` | Enter/create a room |
| `/rooms` | List rooms |
| `/room` | Current room |
| `/owner` | Room owner |
| `/kick` `/mute` `/ban` | Owner moderation |

</details>

<details>
<summary><b>Trust & security</b></summary>

| Command | Description |
|---------|-------------|
| `/fingerprint [nick]` | Key fingerprint + a deterministic **randomart** picture of the key |
| `/verify <nick>` | SAS code (~40-bit) + QR + key randomart for out-of-band verification |
| `/verify-confirm <nick>` | Mark peer as verified |
| `/trust <nick>` / `/trustlist` | Accept new key / trust status |
| `/backup [path]` | Encrypted backup of identity + verified peers (restore at startup) |
| `/deniable [on\|off]` | Plausible-deniability mode |
| `/cover [on\|constant\|off]` | Cover traffic — `on` = jittered decoys, `constant` = steady-rate paced channel |
| `/ephemeral <30s\|5m\|1h\|off>` | Self-destructing messages |
| `/receipts [on\|off]` | Send read receipts (✓✓) |
| `/audit [n]` | Local audit log |

</details>

<details>
<summary><b>History & files</b></summary>

| Command | Description |
|---------|-------------|
| `/file <path>` | Offer a file (≤ 50MB) — the recipient must `/accept`; transfers resume |
| `/accept [id]` / `/reject [id]` | Accept / decline an incoming file offer |
| `/img [path]` | Render the last received image in **full resolution** (kitty/iTerm2) |
| `/search <term>` | Search the encrypted local history |
| `/history [n]` | Last n messages from history |
| `/retention <7d\|24h\|30m>` | Purge local history older than the given age |
| `/export [path]` | Export history as .txt or .json (plaintext!) |

</details>

<details>
<summary><b>Presence & fun</b></summary>

| Command | Description |
|---------|-------------|
| `/away [reason]` / `/back` | Mark yourself away |
| `/status <text\|off>` | Free-form status — emojis welcome (`/status :fire: coding`) |
| `/react <emoji>` | React to the last message |
| `/edit` `/delete` | Edit/delete your last message |
| `/pin` `/unpin` `/pins` | Pin messages |
| `/sound` `/notify` | Sound / desktop notifications |
| `/clear` | Clear the chat |

</details>

Typing `:fire:` anywhere becomes 🔥 (Tab autocompletes shortcodes). PageUp/PageDown scroll the history. **Alt+Enter** (or Shift+Enter where the terminal supports it, plus Ctrl+J) inserts a newline for multi-line messages; Enter sends. Markdown works: \`code\`, **bold**, *italic*, and links are highlighted. Received images preview inline (half-blocks) and render full-res with `/img` on kitty/iTerm2. Day separators and message grouping keep the log clean.

## 🔒 Security model

- The relay is **zero-knowledge**: it routes ciphertext and metadata-padded
  payloads, nothing else. Read receipts, reactions, presence — all of it is
  indistinguishable ciphertext to the server.
- **Traffic-analysis resistance**: every ciphertext is padded up to fixed
  buckets so the relay can't read message length; file chunks are padded to a
  uniform size so the exact file size doesn't leak either. `/cover on` adds
  jittered decoy traffic and `/cover constant` paces your messages through a
  steady-rate channel (decoys fill the idle slots) so the relay can't tell
  active chatting from idle. Decoys are dropped silently by the receiver.
- **Anti-replay** via monotonic nonces, **key rotation** every hour with a
  grace window, **secure memory wipe** (`sodium_memzero`) after use.
- Session state and local history are encrypted at rest with
  **Argon2id + XSalsa20-Poly1305** — no passphrase, no persistence.
- Threat analysis and protocol details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
  Found something? See [SECURITY.md](SECURITY.md).

## 🧪 Development

```bash
npm run server:dev      # relay with auto-reload
npm test                # 62 tests (crypto, ratchet, invites, history, transfers…)
npm run validate        # lint + prettier + tests — what the CI runs
```

CI runs on every push/PR (Node 20 & 22). Tags `v*` trigger tests + a GitHub
Release automatically.

## 📄 License

[MIT](LICENSE) — do good things with it.
