# CipherMesh

Chat seguro para rede local (LAN) com criptografia ponta-a-ponta real (E2EE).

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
- **P2P com mDNS** — modo sem servidor, peers descobertos automaticamente na LAN

## Comandos no chat

| Comando | Descricao |
|---------|-----------|
| `/help` | Lista de comandos |
| `/users` | Mostra usuarios online |
| `/fingerprint` | Mostra seu fingerprint |
| `/fingerprint <nick>` | Fingerprint de outro usuario |
| `/verify <nick>` | Mostra codigo SAS para verificacao |
| `/verify-confirm <nick>` | Confirma verificacao do peer |
| `/trust <nick>` | Aceita nova chave de um peer |
| `/trustlist` | Status de confianca dos peers |
| `/clear` | Limpa o chat |
| `/file <caminho>` | Envia arquivo (max 50MB) |
| `/sound [on\|off]` | Notificacoes sonoras |
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
