# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

- Use GitHub's [private vulnerability reporting](https://github.com/FelipeKreulich/secret-chat-lan/security/advisories/new), or
- Email: felipek2002k@gmail.com

Include steps to reproduce and, if possible, the impact you see. You should get
a first response within a few days.

## Supported versions

Only the latest code on `master` is supported. There are no long-term support
branches.

## Cryptography overview

| Layer | Primitive |
|-------|-----------|
| Key exchange | Curve25519 (libsodium `crypto_box`) |
| Message encryption | XSalsa20-Poly1305 |
| Forward secrecy | Double Ratchet (per-message keys) |
| At-rest encryption (state, history) | Argon2id KDF + XSalsa20-Poly1305 |
| Integrity | Poly1305 MAC, SHA-256 for file transfers |
| Key storage | `sodium_malloc` locked pages, `sodium_memzero` wipes |

The relay server is zero-knowledge by design: it forwards ciphertext and never
holds decryption keys. TLS on the transport is self-signed by default —
end-to-end trust comes from TOFU pinning and SAS voice verification, not from
the TLS certificate.

## Known limitations

- Metadata (who talks to whom, when, message sizes bucketed by padding) is
  visible to the relay operator.
- The `/export` command writes **plaintext** files by explicit user action.
- Nicknames are not authenticated identities — trust is established per-key
  via TOFU/SAS, not per-name.
