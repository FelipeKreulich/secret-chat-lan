# CipherMesh

Chat seguro para rede local (LAN) — e pela internet via [Tailscale](docs/SETUP.md#conectando-pela-internet-tailscale) — com criptografia ponta-a-ponta real (E2EE).

O servidor **nunca** tem acesso ao conteudo das mensagens — ele apenas retransmite payloads cifrados.

```
Cliente A  ──[payload cifrado]──>  Servidor (relay cego)  ──[payload cifrado]──>  Cliente B
```

## Stack

| Camada | Tecnologia |
|--------|-----------|
| Criptografia | **Curve25519 + XSalsa20-Poly1305** (libsodium via sodium-native) |
| Transporte | **WebSocket** (ws) |
| Interface | **Terminal UI** (blessed + chalk + figlet + gradient-string) |
| Deploy | **Docker** (opcional) |

## Quick Start

### Servidor

```bash
# Com Docker
docker compose up -d

# Ou direto
npm run server
```

### Cliente

```bash
git clone https://github.com/FelipeKreulich/secret-chat-lan.git
cd secret-chat-lan
npm install
npm run client
```

O cliente pede seu nickname e o IP do servidor (ex: `192.168.1.142:3600`).

### Modo P2P (sem servidor)

```bash
npm run p2p
```

Peers sao descobertos automaticamente via mDNS na LAN. Conexao direta, sem servidor central. Mesma criptografia E2E.

### Pela internet (redes diferentes)

Com [Tailscale](https://tailscale.com) instalado nos dois lados, o chat funciona entre redes diferentes sem port forwarding — o servidor mostra o IP Tailscale no banner com o rotulo `Internet`, e o amigo conecta nele (ex: `100.101.102.103:3600`). Passo a passo em [docs/SETUP.md](docs/SETUP.md#conectando-pela-internet-tailscale).

Pra facilitar, quem ja esta no chat pode rodar `/invite <ip>:3600` — gera uma string `ciphermesh://ip:porta/sala` (com QR code no terminal) que o convidado cola direto no prompt `Servidor` e ja cai na sala certa.

## Seguranca

- Chaves geradas em memoria segura (`sodium_malloc`) — nunca tocam o disco
- Servidor **zero-knowledge** — nao tem acesso ao conteudo
- Autenticacao via Poly1305 MAC — detecta adulteracao
- Protecao anti-replay via nonce monotonicamente crescente
- **Perfect Forward Secrecy** — Double Ratchet com chave unica por mensagem
- **TOFU (Trust On First Use)** — detecta mudanca de chave publica (possivel MITM)
- **SAS (Short Authentication String)** — codigo de 6 digitos para verificacao por voz
- **Secure memory wipe** — plaintext wipado da memoria apos uso (`sodium_memzero`)
- **Reconnect com estado** — ratchets e chaves cifrados com Argon2id + XSalsa20-Poly1305
- **Historico local cifrado (opt-in)** — so existe com passphrase, mesmo esquema Argon2id + XSalsa20-Poly1305; mensagens efemeras e deniable nunca sao gravadas
- **Read receipts cifrados** — o ✓✓ viaja como payload E2EE comum; o servidor nao distingue receipt de mensagem
- **P2P com mDNS** — modo sem servidor, peers descobertos automaticamente na LAN

## Comandos no chat

| Comando | Descricao |
|---------|-----------|
| `/help` | Lista de comandos |
| `/users` | Mostra usuarios online |
| `/msg <nick> <texto>` | Envia mensagem privada (DM) |
| `/join <sala>` | Entra em uma sala (server mode) |
| `/invite [host:porta]` | Gera convite `ciphermesh://` com QR code |
| `/rooms` | Lista salas disponiveis (server mode) |
| `/room` | Mostra sala atual (server mode) |
| `/fingerprint` | Mostra seu fingerprint |
| `/fingerprint <nick>` | Fingerprint de outro usuario |
| `/verify <nick>` | Mostra codigo SAS para verificacao |
| `/verify-confirm <nick>` | Confirma verificacao do peer |
| `/trust <nick>` | Aceita nova chave de um peer |
| `/trustlist` | Status de confianca dos peers |
| `/search <termo>` | Busca no historico local cifrado |
| `/history [n]` | Ultimas n mensagens do historico |
| `/clear` | Limpa o chat |
| `/file <caminho>` | Envia arquivo (max 50MB); imagens ganham preview no chat |
| `/receipts [on\|off]` | Confirmacao de leitura (✓✓) |
| `/sound [on\|off]` | Notificacoes sonoras |
| `/notify [on\|off]` | Notificacoes desktop (Windows toast) |
| `/quit` | Sai do chat |

## Estrutura

```
src/
├── server/       # WebSocket server (relay cego)
├── client/       # Terminal UI + conexao + TOFU
├── crypto/       # E2EE (libsodium), Double Ratchet, TrustStore, StateManager
├── p2p/          # Modo P2P (mDNS discovery, conexoes diretas)
├── protocol/     # Tipos de mensagem + validacao
└── shared/       # Constantes, logger, banner
```

## Desenvolvimento

```bash
npm run server:dev    # Servidor com auto-reload
npm run p2p           # Modo P2P (sem servidor, mDNS)
npm run lint          # Verificar codigo
npm run test          # Rodar testes
npm run validate      # Lint + format + testes
```

## Documentacao

- [Setup e Deploy](docs/SETUP.md) — Docker, conexao LAN, troubleshooting
- [Arquitetura](docs/ARCHITECTURE.md) — Design tecnico, fluxo criptografico, analise de ameacas

## Licenca

MIT
