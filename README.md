# SecureLAN Chat

Chat seguro para rede local (LAN) com criptografia ponta-a-ponta real (E2EE).

O servidor **nunca** tem acesso ao conteudo das mensagens — ele apenas retransmite payloads cifrados.

## Principio

```
Cliente A  ──[payload cifrado]──>  Servidor (relay cego)  ──[payload cifrado]──>  Cliente B
```

- Criptografia: **Curve25519 + XSalsa20-Poly1305** (libsodium)
- Transporte: **WebSocket** (ws)
- Interface: **Terminal UI** (blessed + chalk)

## Requisitos

- **Node.js >= 20** (LTS)
- Rede local (LAN) — todos os participantes na mesma rede

## Instalacao

```bash
git clone <repo-url>
cd securelan-chat
npm install
```

## Uso

### Iniciar servidor

```bash
npm run server
```

O servidor imprime o IP local e a porta (default: 3600).

### Conectar como cliente

```bash
npm run client
```

O cliente pede:
1. Seu nickname
2. IP:porta do servidor (default: `localhost:3600`)

### Comandos no chat

| Comando | Descricao |
|---------|-----------|
| `/help` | Lista de comandos |
| `/users` | Mostra usuarios online |
| `/fingerprint` | Mostra fingerprint da sua chave publica |
| `/fingerprint <nick>` | Mostra fingerprint de outro usuario |
| `/clear` | Limpa a tela do chat |
| `/quit` | Sai do chat |

## Seguranca

- Chaves geradas em memoria segura (`sodium_malloc`)
- Chaves **nunca** tocam o disco
- Servidor nao tem acesso ao conteudo
- Autenticacao via Poly1305 MAC
- Protecao anti-replay via nonce monotonicamente crescente
- Verificacao de identidade via fingerprint

Para detalhes completos, veja [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Desenvolvimento

```bash
npm run server:dev    # Servidor com auto-reload
npm run lint          # Verificar codigo
npm run format        # Formatar codigo
npm run test          # Rodar testes
npm run validate      # Lint + format check + testes
```

## Estrutura

```
src/
├── server/       # WebSocket server (relay)
├── client/       # Terminal UI + conexao
├── crypto/       # Criptografia E2EE (libsodium)
├── protocol/     # Tipos de mensagem + validacao
└── shared/       # Constantes + logger
```

## Licenca

MIT
