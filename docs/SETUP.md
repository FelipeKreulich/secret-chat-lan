# CipherMesh — Setup and Deploy

A complete guide to running the server and connecting clients on the local network.

---

## Option 1: Docker (recommended for the server)

### Requirements

- [Docker](https://docs.docker.com/get-docker/) installed

### Bring up the server

```bash
# Build + start em background
npm run docker:up

# Ou manualmente
docker compose up -d --build
```

The server will run on port `3600` (with TLS/`wss://` by default) and be reachable across the entire local network — and, if you use Tailscale, also over the internet (see the section below).

### `ADVERTISE_IP` — show the right IP in the banner (Docker)

Inside Docker, the container runs on the Docker bridge (`172.x`) and **cannot see the host's interfaces** (neither the LAN nor `tailscale0`). For that reason, in Docker the banner cannot figure out on its own which address to advertise.

The `ADVERTISE_IP` variable solves this — pass one or more host IPs (comma-separated) and the banner will display the correct URLs. Create a `.env` file (already in `.gitignore`) next to `docker-compose.yml`:

```bash
# .env — IPs do host anunciados no banner (separados por virgula)
#   LAN:       ipconfig getifaddr en0   (macOS)  /  hostname -I  (Linux)
#   Tailscale: tailscale ip -4
ADVERTISE_IP=192.168.1.7,100.73.206.23
```

The banner then shows:

```
╭─────────────  SERVER  ──────────────╮
│   Porta    3600                     │
│   Local    wss://192.168.1.7:3600   │   ← rede local
│   Internet wss://100.73.206.23:3600 │   ← Tailscale (fora da rede)
│   Status   ● Online                 │
╰─────────────────────────────────────╯
```

> `ADVERTISE_IP` only changes **what the banner displays** — it does not restrict who connects. The compose `3600:3600` mapping already exposes the port on **all** of the host's interfaces at once, so the server responds on the LAN and on Tailscale regardless of this.

### View the server logs

```bash
npm run docker:logs

# Ou
docker compose logs -f
```

### Stop the server

```bash
npm run docker:down
```

### Check whether it is running

```bash
docker ps
# Deve mostrar: ciphermesh-server
```

---

## Option 2: Node.js directly

### Requirements

- Node.js >= 20

### Start the server

```bash
npm run server
```

The server prints all the LAN IPs and the port.

---

## Connect as a client

### Client requirements

- Node.js >= 20
- Git (to clone the repo)

### Step by step (for you or your friend)

```bash
# 1. Clonar o repositorio
git clone https://github.com/FelipeKreulich/secret-chat-lan.git

# 2. Entrar na pasta
cd secret-chat-lan

# 3. Instalar dependencias
npm install

# 4. Conectar ao chat
npm run client
```

The client will ask for:
1. **Nickname** — your name in the chat
2. **Server** — the IP of whoever is running the server (e.g., `192.168.1.142:3600`)

### How do you find out the server's IP?

When the server starts, it shows the available addresses:

```
╭────────────────  SERVER  ────────────────╮
│   Porta    3600                          │
│   Local    wss://192.168.1.142:3600      │
│   Status   ● Online                      │
╰──────────────────────────────────────────╯
```

Your friend types `192.168.1.142:3600` when the client asks for the server (there's no need to type `wss://` — the client completes it on its own and accepts the self-signed certificate automatically).

---

## Typical scenario

```
Tua maquina (servidor)                    Maquina do amigo (cliente)
┌──────────────────────┐                 ┌──────────────────────┐
│  docker compose up   │                 │  npm run client      │
│  (ou npm run server) │                 │                      │
│                      │    Wi-Fi/LAN    │  Servidor:           │
│  Porta 3600 aberta ◄├─────────────────┤  192.168.1.142:3600  │
│                      │                 │                      │
│  Tu tambem pode      │                 │  Tudo criptografado  │
│  rodar npm run client│                 │  ponta-a-ponta       │
└──────────────────────┘                 └──────────────────────┘
```

1. You bring up the server (Docker or Node)
2. You open another terminal and run `npm run client` too
3. Your friend clones the repo, installs, and runs `npm run client`
4. Both pick nicknames and connect to your IP
5. E2EE chat up and running

---

## Connecting over the Internet (Tailscale)

LAN mode only works with everyone on the **same network**. To talk with someone on **another network** (another house, another city, another country), the simplest way is [Tailscale](https://tailscale.com): a free mesh VPN (based on WireGuard) that creates a "virtual LAN" — the **tailnet** — between your machines. It works even behind CGNAT and double NAT, **without opening a port on the router**.

The chat's encryption remains **end-to-end** — Tailscale is only the transport. Even if the Tailscale network were compromised, the content of messages stays protected by E2EE (and there is still identity verification with `/verify`).

### The concept that confuses everyone: the IP belongs to the MACHINE, not something you choose

Each device on the tailnet gets its own **fixed IP** in the `100.x` range (CGNAT `100.64.0.0/10`) — this is **that machine's identity** on the network. Consequences:

- The server is reachable at the Tailscale IP of the **machine that runs the server**.
- You **do not "choose"** a `100.x` IP for the server. If you want the server to be `100.a.b.c`, you need to run the server **on that specific machine**.
- `tailscale status` on a machine lists the 100.x IPs of **each** device (yours and the others'). Your server's is the one on the machine where `docker compose up` / `npm run server` runs.

### 1. Install Tailscale (on both sides)

```bash
# Linux
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# macOS  (app de menu; ou via Homebrew)
brew install --cask tailscale     # depois abra o app e faca login

# Windows
winget install tailscale.tailscale
```

`tailscale up` (or the app) opens a URL in the browser to log in (Google, GitHub, Microsoft, email...).

> **macOS:** the command-line `tailscale` is often **not on the PATH**. If `tailscale ip -4` gives "command not found", use the binary inside the app:
> ```bash
> /Applications/Tailscale.app/Contents/MacOS/Tailscale ip -4
> ```

### 2. Put both machines on the same tailnet

Separate accounts **cannot see each other** by default. Choose an option:

- **Invite the other person to your tailnet**: [admin console](https://login.tailscale.com/admin/users) → **Users** → **Invite users**. The free plan (Personal) accepts up to ~3 users and 100 devices.
- **Share only the server machine**: admin console → **Machines** → `...` on the server machine → **Share** — the other person accepts the link and can then see **only** that machine (good for privacy).

Confirm that both show up **online** (green dot) in `tailscale status` or in the admin console. If the peer is `offline`, it will **not** be able to connect until it opens Tailscale.

### 3. Find the server's Tailscale IP

On the machine that **runs the server**:

```bash
tailscale ip -4
# ex: 100.73.206.23
```

This IP also appears in the server banner with the `Internet` label (outside Docker, the banner detects the Tailscale interface on its own; **inside Docker**, set `ADVERTISE_IP` — see the Docker section above).

### 4. The server responds on the LAN AND on Tailscale at the same time

The server does a `bind` on `0.0.0.0:3600`, that is, it listens on **all** of the machine's interfaces simultaneously. You **do not need** to restart or choose the network — the same server is reachable via:

- `wss://<IP-LAN>:3600` — for those on the **same local network** (e.g., `wss://192.168.1.7:3600`)
- `wss://<IP-Tailscale>:3600` — for those **outside the network**, on the tailnet (e.g., `wss://100.73.206.23:3600`)

### 5. Which address to give to whom

| Person | Situation | Address you give |
|---|---|---|
| Friend on **another network**, with Tailscale | on your tailnet | `<IP-Tailscale>:3600` (e.g., `100.73.206.23:3600`) |
| Colleague on the **same network**, without Tailscale | same LAN | `<IP-LAN>:3600` (e.g., `192.168.1.7:3600`) |
| You yourself, on the server machine | localhost | `localhost:3600` |

> A peer **without** Tailscale, but on your local network, **does not need** Tailscale — it connects directly via the LAN IP. Tailscale is only needed for those **outside** the network.

### 6. Connect

Whoever hosts brings up the server as usual (`docker compose up -d` or `npm run server`). The other person runs `npm run client` and, when asked for the server, provides the IP + port:

```
Servidor: 100.73.206.23:3600
```

There's no need to type `wss://` — the client completes it on its own and **accepts the self-signed certificate automatically**. On the first connection the client **pins the certificate fingerprint** (TOFU); if it changes later, the chat displays an alert.

**Shortcut — invite with a QR:** whoever hosts can run, inside the chat:

```
/invite 100.73.206.23:3600
```

This outputs a `ciphermesh://...` string **with a QR code** that the other person pastes directly into the `Servidor` prompt (it goes straight into the invite's room).

### Tailscale troubleshooting

- **`tailscale status`** — lists the tailnet's machines and whether they are online. An `offline` peer does not connect until it opens Tailscale.
- **`tailscale ping 100.x.y.z`** — tests direct connectivity to the peer (it should respond via DERP or directly).
- **Host firewall** — allow inbound port `3600`. On macOS: Settings → Network → Firewall. On Windows: `netsh advfirewall firewall add rule name="CipherMesh" dir=in action=allow protocol=TCP localport=3600`.
- **Docker** — the compose `3600:3600` mapping already exposes the port on all of the host's interfaces (including `tailscale0`), so the connection over the tailnet works; `ADVERTISE_IP` only helps the **banner** show the right IP.
- **"Connects and drops" / only the LAN works** — confirm that both are on the **same tailnet** (not just installed) and online.
- **Corporate/hotel Wi-Fi with _client isolation_ (AP isolation)** — devices on the same network cannot see each other; in that case Tailscale (or a cable/another AP) resolves it even while "on the same network".
- **Self-signed certificate** — normal; the client accepts it on its own and uses E2EE + `/verify` as the real identity protection.

---

## Chat commands

Run `/help` in the chat for the **full list**. The main ones:

| Command | Description |
|---------|-----------|
| `/help` | Full list of commands |
| `/users` | Online users |
| `/msg <nick> <texto>` | Private message (DM) |
| `/invite <ip>:<porta>` | Generate a `ciphermesh://` invite + QR |
| `/fingerprint [nick]` | Key fingerprint + randomart |
| `/verify <nick>` | SAS code + QR + randomart to verify identity |
| `/verify-confirm <nick>` | Mark the peer as verified |
| `/file <caminho>` | Send a file (the other person accepts with `/accept`) |
| `/accept` · `/reject` | Accept / decline an offered file |
| `/img [caminho]` | Render the last received image at high resolution (kitty/iTerm2) |
| `/join <sala>` · `/rooms` · `/room` | Rooms (channels) |
| `/backup [caminho]` | Encrypted backup of identity + trust |
| `/deniable [on\|off]` | Deniable mode (symmetric crypto) |
| `/ephemeral <tempo>` | Ephemeral messages |
| `/retention <tempo>` | Purge old local history |
| `/nick <novo>` | Change nickname (before joining) |
| `/clear` · `/quit` | Clear the chat / quit |

---

## Troubleshooting

### "Connection refused" / does not connect

- Check that the server is running: `docker ps` or check the terminal
- Check that everyone is on the **same Wi-Fi/LAN** (or the same tailnet, in internet mode)
- Check that the **firewall** is not blocking port 3600
  - Windows: `Configuracoes > Firewall > Permitir app > Node.js`
  - Or: `netsh advfirewall firewall add rule name="CipherMesh" dir=in action=allow protocol=TCP localport=3600`
- Test whether the port responds: `curl ws://IP:3600` or open `http://IP:3600` in the browser (it will error out, but if the port connects it is open)

### "npm install" fails on sodium-native

`sodium-native` needs to compile C code. Requirements:
- **Windows**: `npm install --global windows-build-tools` or install the Visual Studio Build Tools
- **Mac**: `xcode-select --install`
- **Linux**: `sudo apt install python3 make g++`

### Docker takes a while to build

Normal the first time — it has to compile sodium-native inside the container. Subsequent builds use the cache and are fast.
