# Hosting a public CipherMesh relay

Everything here is for running a relay on the open internet. For LAN or
Tailscale use, the root `docker-compose.yml` is simpler and already enough.

## What you need

- A host with a public IP (a €4–5/month VPS is plenty — the relay only shuffles
  ciphertext; CPU and RAM are near idle)
- A domain name pointing at it (`A`/`AAAA` record)
- Ports 80 and 443 open

## Deploy

```bash
git clone https://github.com/FelipeKreulich/secret-chat-lan.git
cd secret-chat-lan
export CIPHERMESH_DOMAIN=hub.example.com
export CIPHERMESH_EMAIL=you@example.com
docker compose -f deploy/docker-compose.public.yml up -d
```

Caddy obtains a Let's Encrypt certificate on first start and renews it
automatically. Your users connect to `hub.example.com:443`.

Prefer no Docker? Each release also ships a standalone relay binary
(`ciphermesh-server-linux-x64` and friends) — run it behind the same Caddy
config.

## What TLS does and does not do here

Messages are end-to-end encrypted before they reach the relay, so TLS is not
what keeps them private — it protects **metadata in transit** (who is
connecting, when) from the network path, and it authenticates the server.

Because a public certificate chains to a real CA, the CipherMesh client
verifies it **strictly**: no trust-on-first-use window, and a host that once
served a CA-valid certificate can never be silently downgraded to a
self-signed one (`src/crypto/CertPinStore.js`).

## Before you open it to strangers

Running a public, anonymous, end-to-end encrypted chat means **you cannot
moderate content** — you can't read it, by design. That is the product, and it
is also the risk. Decide deliberately:

- The built-in limits already cap connections per IP, total connections,
  message rate, and payload size (`src/shared/constants.js`). Tune them for
  your box before announcing anything.
- Rooms are ephemeral: they exist only while someone is inside, and private
  rooms keep their password verifier in memory only. Nothing is persisted
  server-side, which is excellent for privacy and means there is nothing to
  hand over — or to recover.
- Publish terms of use and an abuse contact. "Zero logs of content by
  architecture" is honest and worth stating plainly.
- Consider a soft launch: share the address in the README first, watch the
  logs for abuse patterns, then announce more widely.

## Operating notes

- **Logs**: the relay logs connections and room events, never content.
- **Certificates**: the `caddy_data` volume holds them. Keep it, or you will
  hit Let's Encrypt rate limits on redeploys.
- **Updates**: `docker compose -f deploy/docker-compose.public.yml up -d --build`
- **Health**: `docker logs ciphermesh-relay` shows the startup banner and the
  live connection count.
