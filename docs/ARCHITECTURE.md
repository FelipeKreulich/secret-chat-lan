# SecureLAN Chat — Documentacao Tecnica Completa

> Chat seguro para rede local (LAN) com criptografia ponta-a-ponta real (E2EE).
> O servidor **nunca** tem acesso ao conteudo das mensagens.

---

## Indice

1. [Visao Geral](#1-visao-geral)
2. [Stack Tecnologica](#2-stack-tecnologica)
3. [Estrutura de Diretorios](#3-estrutura-de-diretorios)
4. [Responsabilidade de Cada Modulo](#4-responsabilidade-de-cada-modulo)
5. [Modelo de Dados e Payloads](#5-modelo-de-dados-e-payloads)
6. [Fluxo Criptografico Detalhado](#6-fluxo-criptografico-detalhado)
7. [Protocolo de Handshake](#7-protocolo-de-handshake)
8. [Fluxo de Comunicacao Passo a Passo](#8-fluxo-de-comunicacao-passo-a-passo)
9. [Estrategia de Inicializacao](#9-estrategia-de-inicializacao)
10. [Seguranca — Analise de Ameacas](#10-seguranca--analise-de-ameacas)
11. [Melhorias Futuras](#11-melhorias-futuras)
12. [Glossario](#12-glossario)

---

## 1. Visao Geral

### O que e

SecureLAN Chat e um sistema de mensagens instantaneas projetado para operar **exclusivamente dentro de uma rede local (LAN)**. Ele utiliza criptografia ponta-a-ponta (E2EE) baseada em **Curve25519 + XSalsa20-Poly1305** (via libsodium), garantindo que o servidor atue apenas como **relay cego** — ele retransmite bytes que nao consegue ler.

### Principio Fundamental

```
Cliente A                  Servidor                  Cliente B
   |                          |                          |
   |--- payload cifrado ----->|                          |
   |                          |--- payload cifrado ----->|
   |                          |                          |
   |  O servidor NAO possui   |                          |
   |  a chave para decifrar   |                          |
```

O servidor conhece **apenas**:
- Quem esta conectado (nickname + ID de sessao)
- Quem enviou pra quem (roteamento)
- Tamanho do payload cifrado
- Timestamps de conexao

O servidor **nunca** conhece:
- Conteudo das mensagens
- Chaves privadas
- Chaves compartilhadas derivadas

### Topologia

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

Este e um modelo **estrela** (star topology). Todos os clientes se conectam ao servidor central. As mensagens sao cifradas antes de sair do cliente e decifradas apenas no cliente destino.

---

## 2. Stack Tecnologica

### Dependencias de Producao

| Pacote | Versao | Papel | Por que esta lib? |
|--------|--------|-------|-------------------|
| **ws** | ^8.18 | WebSocket server/client | Implementacao WebSocket mais madura e performatica para Node.js. Zero dependencias. Suporta binary frames nativamente (essencial para payloads cifrados). Usado por milhares de projetos em producao. |
| **sodium-native** | ^4.3 | Criptografia | Binding nativo da **libsodium** para Node.js. Roda em C compilado (nao e JS puro), oferecendo performance real e seguranca auditada. A libsodium e considerada a biblioteca criptografica moderna mais segura e facil de usar. Usada por Signal, Discord, Wireguard. |
| **blessed** | ^0.1.81 | Terminal UI | Biblioteca para construir interfaces ricas no terminal. Suporta layouts com boxes, inputs, scrolling, cores, borders — similar a ncurses mas em JS. Permite criar UI estilo app moderno sem sair do terminal. |
| **chalk** | ^5.4 | Cores no terminal | Formatacao de texto colorido no terminal. Usa para destacar nicks, timestamps, erros, status. ESM-only na v5 (compativel com nosso `"type": "module"`). |
| **play-sound** | ^1.1 | Audio | Reproduz arquivos de audio (mp3) para notificacoes sonoras. Usa players nativos do SO (mplayer, aplay, cmdmp3). |

### Por que sodium-native e nao tweetnacl?

| Criterio | sodium-native | tweetnacl |
|----------|--------------|-----------|
| Implementacao | C (libsodium compilada) | JavaScript puro |
| Performance | ~100x mais rapido | Lento |
| Auditoria | Formalmente auditada | Auditada mas JS puro |
| Secure memory | Sim (`sodium.sodium_malloc`) | Nao |
| Constant-time | Garantido pelo C | Best-effort em JS |
| Side-channel resistance | Alta | Baixa (JS engine pode otimizar) |

**sodium-native** aloca memoria segura que e:
- Protegida contra swap (mlock)
- Zerada ao ser liberada (sodium_memzero)
- Protegida contra leitura por outros processos

### Dependencias de Desenvolvimento

| Pacote | Papel |
|--------|-------|
| **eslint** ^9.17 | Linting — garante qualidade e consistencia do codigo |
| **@eslint/js** ^9.17 | Configuracao base recomendada do ESLint |
| **globals** ^15.14 | Definicoes de globals (node, browser) para ESLint |
| **prettier** ^3.4 | Formatacao automatica — codigo consistente sem debates de estilo |

### Node.js >= 20

Requisito minimo: Node.js 20 LTS. Motivos:
- `node:test` nativo (sem Jest/Mocha)
- `node:crypto` com APIs modernas
- `--watch` nativo (sem nodemon)
- ESM estavel
- Performance melhorada do V8

---

## 3. Estrutura de Diretorios

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
│   │   └── TrustStore.js        # TOFU + SAS (persistencia de fingerprints)
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
│   └── nonce.test.js            # Testes do gerenciador de nonces
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

## 4. Responsabilidade de Cada Modulo

### 4.1 Server

#### `src/server/index.js` — Entry Point
- Inicializa o servidor WebSocket na porta configurada (default: 3600)
- Registra handlers de conexao/desconexao
- Graceful shutdown (SIGINT, SIGTERM)
- Imprime informacoes de rede local (IP, porta)

#### `src/server/WebSocketServer.js` — Gerenciamento WebSocket
- Wrapper sobre `ws.WebSocketServer`
- Configura limites: `maxPayload` (64KB), heartbeat (ping/pong a cada 30s)
- Detecta clientes desconectados via heartbeat
- Emite eventos tipados: `connection`, `message`, `close`, `error`
- Nao interpreta conteudo — trata tudo como `Buffer` opaco

#### `src/server/SessionManager.js` — Sessoes
- Mantém mapa de sessoes ativas: `Map<sessionId, { ws, nickname, publicKey, connectedAt }>`
- Gera session IDs com `crypto.randomUUID()`
- Broadcast de lista de usuarios quando alguem entra/sai
- Rejeita nicknames duplicados
- Timeout de sessao inativa (configurable)
- **Armazena chave publica apenas para redistribuir** — nao e segredo, e identidade

#### `src/server/MessageRouter.js` — Roteamento
- Recebe payloads do tipo `encrypted_message`
- Valida estrutura (tem `to`, `from`, `payload`)
- **Nao abre `payload`** — apenas verifica campos de roteamento
- Encaminha para o WebSocket do destinatario
- Se destinatario offline e foi recentemente desconectado, enfileira na OfflineQueue
- Retorna erro se destinatario nao encontrado e sem historico recente
- Rate limiting basico: max 30 mensagens/segundo por cliente

#### `src/server/OfflineQueue.js` — Fila Offline
- Armazena mensagens cifradas (opacas) para peers desconectados
- Chaveada por nickname + publicKey (garante que so entrega se reconectar com mesma chave)
- Limites: max 100 msgs/peer, max 1000 total, max 1h de idade
- Se peer reconecta com chave diferente (novo client), descarta fila
- Cleanup periodico a cada 5min
- Fila perde-se ao reiniciar o servidor (in-memory)

### 4.2 Client

#### `src/client/index.js` — Entry Point
- Pede nickname ao usuario
- Pede IP:porta do servidor (default: localhost:3600)
- Inicializa KeyManager (gera par de chaves)
- Mostra fingerprint da chave publica para verificacao
- Conecta ao servidor e inicia a UI

#### `src/client/UI.js` — Interface Blessed
- Layout dividido em 3 areas:

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

- Status bar mostra: nome do chat, usuarios online, indicador E2E
- Chat area com scroll automatico e manual
- Input com historico (setas cima/baixo)
- Cores diferenciadas por usuario (chalk)
- Comandos especiais: `/quit`, `/users`, `/fingerprint`, `/clear`, `/file`, `/sound`, `/help`
- Indicador de "digitando..." animado com suporte a multiplos peers
- Notificacoes sonoras (toggle via `/sound on|off`)
- Barra de progresso para transferencia de arquivos
- Notificacoes de entrada/saida de usuarios

#### `src/client/Connection.js` — WebSocket Client
- Conecta via `ws` ao servidor
- Reconnect automatico com backoff exponencial (1s, 2s, 4s, 8s, max 30s)
- Ping/pong para detectar desconexao
- Serializa/deserializa mensagens do protocolo (JSON para controle, Buffer para dados cifrados)
- Emite eventos para o ChatController

#### `src/client/ChatController.js` — Orquestrador
- Conecta: UI <-> Connection <-> Crypto
- Fluxo de envio: UI input -> cifrar -> Connection send
- Fluxo de recepcao: Connection receive -> decifrar -> UI display
- Gerencia estado: lista de peers, chaves publicas recebidas, chaves compartilhadas derivadas
- Executa handshake com cada novo peer
- Valida fingerprints
- Gerencia transferencia de arquivos via FileTransfer
- Notificacao sonora ao receber mensagens de texto

#### `src/client/FileTransfer.js` — Transferencia de Arquivos
- Envio: le arquivo, divide em chunks de 48KB, cifra cada chunk E2E via broadcast
- Recepcao: reassembla chunks, verifica SHA-256, salva em `./downloads/`
- Throttling: max 25 chunks/sec (abaixo do rate limit de 30/sec)
- Timeout: 30s para transfers incompletos
- Suporte a arquivos ate 50MB

### 4.3 Crypto

#### `src/crypto/KeyManager.js` — Chaves
- Gera par Curve25519 com `sodium.crypto_box_keypair()`
- Armazena em `sodium.sodium_malloc()` (memoria segura, nao vai pro swap)
- Exporta chave publica como `Buffer` (para enviar ao servidor)
- Gera fingerprint: `SHA-256(publicKey)` formatado como `XXXX:XXXX:XXXX:XXXX`
- Metodo `destroy()` que chama `sodium.sodium_memzero()` nas chaves
- **Nunca** serializa chave privada para disco, log, ou rede

#### `src/crypto/MessageCrypto.js` — Cifra/Decifra
- **Cifrar**: `sodium.crypto_box_easy(message, nonce, theirPublicKey, mySecretKey)`
- **Decifrar**: `sodium.crypto_box_open_easy(ciphertext, nonce, theirPublicKey, mySecretKey)`
- A funcao `crypto_box` usa internamente:
  - **X25519**: Diffie-Hellman para derivar chave compartilhada
  - **XSalsa20**: Stream cipher para confidencialidade
  - **Poly1305**: MAC para autenticidade e integridade
- Retorna `{ ciphertext: Buffer, nonce: Buffer }`
- Valida tamanho minimo do ciphertext (MAC de 16 bytes)

#### `src/crypto/Handshake.js` — Gerenciamento de Peers
- Registra chaves publicas de peers recebidas via servidor
- Valida tamanho da chave publica (32 bytes Curve25519)
- Armazena chaves publicas em `Map<peerId, publicKey>`
- Expoe acesso a chave secreta local para uso em `crypto_box_easy`
- Metodo `removePeer()` para limpeza ao desconectar
- Metodo `destroy()` para limpar todo estado

#### `src/crypto/DoubleRatchet.js` — PFS (Perfect Forward Secrecy)
- Implementacao simplificada do Double Ratchet (Signal-style)
- Cada mensagem usa uma chave unica derivada, destruida apos uso
- DH ratchet: `crypto_scalarmult` (X25519) para gerar novo DH output a cada turno
- KDF_RK: `BLAKE2b-512(rootKey, dhOutput)` → novo rootKey + chainKey
- KDF_CK: `BLAKE2b-256(chainKey, 0x01)` → messageKey; `BLAKE2b-256(chainKey, 0x02)` → nextChainKey
- Cifragem: `crypto_secretbox_easy` (XSalsa20-Poly1305 simetrico) com messageKey derivada
- Gerenciamento de chaves puladas (out-of-order messages) com TTL de 60s
- Destruicao imediata de chaves apos uso (`sodium_memzero`)
- Fallback automatico para chaves estaticas quando ratchet nao disponivel

#### `src/crypto/TrustStore.js` — TOFU + SAS
- **TOFU (Trust On First Use)**: Persiste fingerprints de peers em `.ciphermesh/trusted-peers.json`
- Detecta mudanca de chave publica (possivel MITM) — similar ao `known_hosts` do SSH
- **SAS (Short Authentication String)**: Codigo de 6 digitos para verificacao fora-de-banda
  - `BLAKE2b-256(sortedPubKeys || "CipherMesh-SAS-v1")` → primeiros 3 bytes → 6 digitos decimais
  - Ambos os lados computam o mesmo valor independentemente
- TrustResult: `NEW_PEER` | `TRUSTED` | `MISMATCH` | `VERIFIED_MISMATCH`
- Rotacao E2E autenticada (`autoUpdatePeer`) preserva status de verificacao
- Rotacao via servidor (nao autenticada) NAO atualiza trust store

#### `src/crypto/NonceManager.js` — Nonces
- Gera nonces de 24 bytes com `sodium.randombytes_buf()`
- Mantem **counter monotonicamente crescente** por peer
- Rejeita nonces repetidos ou menores que o ultimo recebido (anti-replay)
- Estrutura do nonce:

```
[  8 bytes: timestamp ms  |  4 bytes: counter  |  12 bytes: random  ]
         anti-replay            sequencia           unicidade
```

### 4.4 Protocol

#### `src/protocol/messages.js` — Tipos de Mensagem

Define os tipos de mensagem do protocolo. Todas as mensagens tem:
```js
{
  type: string,       // tipo da mensagem
  version: 1,         // versao do protocolo
  timestamp: number   // Date.now() do remetente
}
```

Tipos:
| Tipo | Direcao | Descricao |
|------|---------|-----------|
| `join` | Client -> Server | Cliente quer entrar (nickname + publicKey) |
| `join_ack` | Server -> Client | Servidor confirma entrada (sessionId + lista de peers) |
| `peer_joined` | Server -> Clients | Novo peer entrou (nickname + publicKey) |
| `peer_left` | Server -> Clients | Peer saiu |
| `key_exchange` | Client -> Server -> Client | Troca de chave publica entre peers |
| `encrypted_message` | Client -> Server -> Client | Mensagem cifrada |
| `error` | Server -> Client | Erro (nickname duplicado, etc) |
| `ping` / `pong` | Bidirecional | Heartbeat |

#### `src/protocol/validators.js` — Validacao
- Valida estrutura JSON de cada tipo de mensagem
- Verifica campos obrigatorios e tipos
- Verifica tamanhos maximos (nickname: 20 chars, payload: 64KB)
- Sanitiza inputs (trim, remocao de caracteres de controle)
- Rejeita mensagens com `version` incompativel

### 4.5 Shared

#### `src/shared/constants.js` — Constantes

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
- Niveis: `debug`, `info`, `warn`, `error`
- Formato: `[HH:MM:SS] [LEVEL] [module] message`
- Nivel configuravel via variavel de ambiente `LOG_LEVEL`
- Nunca loga conteudo de mensagens ou chaves privadas
- Loga apenas metadados: conexoes, desconexoes, erros

---

## 5. Modelo de Dados e Payloads

### 5.1 Mensagem de Join (client -> server)

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

### 5.3 Mensagem Cifrada (client -> server -> client)

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

**Nota**: O campo `payload` e completamente opaco para o servidor. Ele apenas le `from` e `to` para roteamento.

### 5.4 Conteudo decifrado (nunca trafega em texto claro)

Apos decifrar `payload.ciphertext`, o resultado e:

```json
{
  "text": "Ola Bob, tudo bem?",
  "sentAt": 1739800001000,
  "messageId": "a1b2c3d4"
}
```

- `sentAt` dentro do payload cifrado permite o receptor validar contra o `timestamp` externo
- `messageId` e um ID aleatorio curto para referencia (nao e UUID, apenas 4 bytes hex)

#### Comandos cifrados (actions)

Alem de mensagens de texto, o payload cifrado pode conter comandos (campo `action`):

```json
{ "action": "clear", "sentAt": 1739800001000 }
```

```json
{ "action": "typing", "sentAt": 1739800001000 }
```

- `clear` — limpa o chat de todos os peers
- `typing` — indica que o remetente esta digitando (debounce de 2s, expira em 3s no receptor)
- `file_offer` — oferece envio de arquivo (transferId, fileName, fileSize, totalChunks, sha256)
- `file_chunk` — envia chunk de arquivo (transferId, chunkIndex, data base64)
- `file_complete` — sinaliza fim da transferencia (transferId)

### 5.5 Notificacao de Peer (server -> clients)

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

### 5.6 Erro (server -> client)

```json
{
  "type": "error",
  "version": 1,
  "timestamp": 1739800003000,
  "code": "NICKNAME_TAKEN",
  "message": "O nickname 'Alice' ja esta em uso"
}
```

Codigos de erro:
| Codigo | Descricao |
|--------|-----------|
| `NICKNAME_TAKEN` | Nickname ja em uso |
| `INVALID_MESSAGE` | Estrutura de mensagem invalida |
| `PEER_NOT_FOUND` | Destinatario nao esta online |
| `RATE_LIMITED` | Muitas mensagens por segundo |
| `PAYLOAD_TOO_LARGE` | Payload excede 64KB |

---

## 6. Fluxo Criptografico Detalhado

### 6.1 Algoritmos Utilizados

| Operacao | Algoritmo | Tamanho | Descricao |
|----------|-----------|---------|-----------|
| Par de chaves | **Curve25519** | 32 bytes cada | Curva eliptica para key exchange |
| Key exchange | **X25519** (ECDH) | 32 bytes resultado | Diffie-Hellman sobre Curve25519 |
| Cifra | **XSalsa20** | stream cipher | Variante do Salsa20 com nonce de 24 bytes |
| MAC | **Poly1305** | 16 bytes tag | Message Authentication Code |
| Nonce | random + counter | 24 bytes | Numero usado uma unica vez |

### 6.2 Por que Curve25519 + XSalsa20-Poly1305?

Esta combinacao (conhecida como **NaCl crypto_box**) foi escolhida porque:

1. **Curva moderna**: Curve25519 foi projetada por Daniel J. Bernstein para ser resistente a timing attacks e ter implementacoes seguras
2. **Authenticated encryption**: XSalsa20-Poly1305 combina confidencialidade + integridade em uma unica operacao atomica (AEAD)
3. **Nonce de 24 bytes**: Grande o suficiente para ser gerado aleatoriamente sem risco pratico de colisao (2^192 combinacoes)
4. **Sem padding oracle**: Stream cipher nao precisa de padding, eliminando toda uma classe de ataques
5. **Resistente a misuse**: Dificil de usar incorretamente (comparado com AES-CBC, AES-CTR manual, etc)

### 6.3 Geracao de Chaves

```
1. Cliente inicia
2. sodium.crypto_box_keypair() gera:
   - publicKey:  32 bytes (pode ser compartilhada)
   - secretKey:  32 bytes (NUNCA sai da memoria do processo)
3. Ambas armazenadas em sodium.sodium_malloc() (secure memory)
4. Fingerprint = SHA256(publicKey) formatada como XXXX:XXXX:XXXX:XXXX
```

### 6.4 Cifragem Autenticada com crypto_box_easy

`crypto_box_easy` faz tudo internamente numa unica operacao atomica:

```
crypto_box_easy(ciphertext, plaintext, nonce, recipientPublicKey, senderSecretKey)

Internamente:
1. X25519 DH:    sharedSecret = ECDH(recipientPub, senderSec)
2. Key derivation: encKey = HSalsa20(sharedSecret, zeros)
3. Cifra:        XSalsa20(plaintext, nonce, encKey) -> ciphertext
4. MAC:          Poly1305(ciphertext) -> tag de 16 bytes
5. Output:       tag || ciphertext (autenticado)
```

A chave compartilhada e derivada implicitamente a cada chamada. O DH garante
que ambos os lados (Alice e Bob) chegam ao mesmo segredo sem troca-lo pela rede.

### 6.5 Cifragem de Mensagem

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

### 6.6 Decifragem de Mensagem

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

### 6.7 Estrutura do Nonce (24 bytes)

```
┌──────────────────┬──────────────┬──────────────────────┐
│  Timestamp (8B)  │ Counter (4B) │    Random (12B)      │
│  ms desde epoch  │ sequencial   │  sodium.randombytes  │
└──────────────────┴──────────────┴──────────────────────┘

- Timestamp: impede replay entre sessoes diferentes
- Counter: garante ordenacao e unicidade dentro da sessao
- Random: garante unicidade mesmo com clocks sincronizados
```

### 6.8 Verificacao de Fingerprint

O fingerprint permite que usuarios verifiquem a identidade um do outro **fora do canal** (por exemplo, pessoalmente ou por telefone):

```
1. Alice ve seu fingerprint: A1B2:C3D4:E5F6:7890
2. Bob ve o fingerprint de Alice: A1B2:C3D4:E5F6:7890
3. Bob confirma pessoalmente com Alice que os valores batem
4. Se nao baterem -> MITM detectado
```

O fingerprint e calculado assim:
```
fingerprint = SHA-256(publicKey)
            = primeiros 8 bytes, formatados em hex com separador ':'
            = "A1B2:C3D4:E5F6:7890"
```

---

## 7. Protocolo de Handshake

### 7.1 Diagrama Completo

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

### 7.2 Passos Detalhados

**Passo 1 — JOIN**: Cliente A gera par de chaves, envia `{ type: "join", nickname: "Alice", publicKey: base64(pubKeyA) }` ao servidor.

**Passo 2 — JOIN_ACK**: Servidor valida nickname (unico?), registra sessao, retorna lista de peers ja conectados com suas chaves publicas.

**Passo 3 — PEER_JOINED**: Servidor notifica todos os clientes existentes que Alice entrou, incluindo a chave publica dela.

**Passo 4 e 5 — Derivacao**: Cada lado computa `crypto_box_beforenm()` com a chave publica do outro e sua propria chave privada. Resultado: mesma chave compartilhada.

**Passo 6 — Mensagem cifrada**: Alice cifra e envia. Servidor retransmite sem ler.

**Passo 7 — Decifragem**: Bob decifra com a chave compartilhada derivada.

### 7.3 Seguranca do Handshake

- A chave publica trafega em texto claro (e seguro — e publica por definicao)
- A chave privada **nunca** sai do processo do cliente
- O servidor ve chaves publicas mas nao consegue derivar a chave compartilhada (precisaria de uma chave privada)
- Um atacante que captura todo o trafego ve apenas chaves publicas + payloads cifrados = inutil sem chave privada

**PFS implementado**: O sistema usa Double Ratchet simplificado para conversas ao vivo. Cada mensagem usa uma chave derivada unica, destruida apos uso. Comprometer uma chave revela no maximo UMA mensagem. Mensagens offline usam chaves estaticas como fallback.

---

## 8. Fluxo de Comunicacao Passo a Passo

### 8.1 Cenario Completo: Alice envia "Ola" para Bob

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

### 8.2 Cenario: Chat em Grupo (broadcast)

Para enviar para todos, Alice cifra **individualmente** para cada peer:

```
Alice -> Bob:     encrypt(msg, nonceAB, sharedKeyAB)
Alice -> Charlie: encrypt(msg, nonceAC, sharedKeyAC)
```

Cada mensagem tem nonce e ciphertext diferentes porque cada chave compartilhada e diferente. O servidor recebe N mensagens e roteia cada uma ao destinatario correto.

**Impacto**: O(N) cifragens por mensagem em grupo. Aceitavel para LAN com poucos usuarios.

---

## 9. Estrategia de Inicializacao

### 9.1 Servidor

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

### 9.2 Cliente

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

## 10. Seguranca — Analise de Ameacas

### 10.1 Modelo de Ameacas

| Ameaca | Mitigacao | Status |
|--------|-----------|--------|
| **Servidor malicioso le mensagens** | Impossivel — servidor nao tem chave privada | Mitigado |
| **Servidor altera mensagens** | Poly1305 MAC detecta adulteracao | Mitigado |
| **Replay de mensagens** | Nonce com timestamp + counter monotonicamente crescente | Mitigado |
| **Man-in-the-Middle (MITM)** | TOFU + SAS (codigo 6 digitos) + fingerprint | Mitigado |
| **Leak de chave privada** | Memoria segura (sodium_malloc + mlock) | Mitigado |
| **Plaintext em memoria** | Secure wipe (sodium_memzero) apos uso | Mitigado |
| **Chave privada no swap** | sodium_malloc() com mlock | Mitigado |
| **Brute force na chave** | Curve25519 = 128 bits de seguranca (~3x10^38 operacoes) | Inviavel |
| **Nonce reuse** | Nonce hibrido (timestamp + counter + random) | Mitigado |
| **Denial of Service** | Rate limiting + maxPayload | Parcial |
| **Forward secrecy** | Double Ratchet — chave unica por mensagem | Mitigado |
| **Metadata analysis** | Padding de mensagens + tamanhos fixos | Parcial |

### 10.2 O que o servidor PODE deduzir (metadata)

Mesmo sem ler conteudo, o servidor sabe:
- **Quem** esta online
- **Quem** fala com quem
- **Quando** as mensagens sao enviadas
- **Tamanho** aproximado das mensagens (pelo tamanho do ciphertext)
- **Frequencia** da comunicacao

Isso e inerente ao modelo estrela. Solucoes:
- Padding de mensagens para tamanho fixo (ofusca tamanho)
- Mensagens dummy periodicas (ofusca frequencia)
- Migrar para P2P (elimina servidor central)

### 10.3 Resistencia a Ataques Conhecidos

| Ataque | Resistente? | Explicacao |
|--------|-------------|-----------|
| Padding oracle | Sim | XSalsa20 e stream cipher, sem padding |
| Timing attack | Sim | libsodium usa comparacoes constant-time |
| Chosen ciphertext | Sim | Poly1305 autentica antes de decifrar |
| Key confusion | Sim | crypto_box usa chaves tipadas (pub/sec) |
| Nonce misuse | Parcial | Nonce hibrido reduz risco, mas XSalsa20 nao e nonce-misuse-resistant (diferente de AES-GCM-SIV) |

---

## 11. Melhorias Futuras

### 11.1 Perfect Forward Secrecy (PFS) — IMPLEMENTADO

**Implementacao**: Double Ratchet simplificado usando primitivos libsodium.

**Modelo hibrido**:
- **Ratchet** para conversas ao vivo (ambos peers online) — cada mensagem usa chave unica
- **Chaves estaticas** (`crypto_box`) como fallback para offline queue e msgs iniciais

**Primitivos usados**:
- `crypto_scalarmult` — DH bruto X25519 para ratchet steps
- `crypto_generichash` (BLAKE2b) — KDF para derivar root keys e chain keys
- `crypto_secretbox_easy` — Cifragem simetrica com chave derivada por mensagem
- `sodium_malloc` / `sodium_memzero` — Memoria segura, destruicao imediata de chaves

**Arquivos**:
- `src/crypto/DoubleRatchet.js` — Classe principal do ratchet (KDF_RK, KDF_CK, encrypt, decrypt, skipped keys)
- Integrado em `Handshake.js` (gerenciamento de ratchets por peer) e `ChatController.js` (wiring)

**Wire format**: Msgs ratcheted incluem `ephemeralPublicKey`, `counter`, `previousCounter` no payload. Msgs estaticas nao tem `ephemeralPublicKey`. Servidor nao afetado (relay opaco).

**Anti-replay**: Ratchet usa counter proprio (nao precisa de NonceManager). Msgs estaticas continuam usando NonceManager.

### 11.2 TOFU + SAS (Verificacao de Identidade) — IMPLEMENTADO

**TOFU (Trust On First Use)**: Ao conectar com um peer pela primeira vez, o fingerprint da chave publica e salvo localmente em `.ciphermesh/trusted-peers.json`. Nas conexoes seguintes, se a chave mudar, o usuario e alertado (similar ao `known_hosts` do SSH).

**SAS (Short Authentication String)**: Codigo de 6 digitos que ambos os lados computam independentemente. Permite verificacao fora-de-banda (por voz, pessoalmente) para confirmar que nao ha MITM.

**Comandos**:
- `/verify <nick>` — Mostra codigo SAS de 6 digitos
- `/verify-confirm <nick>` — Marca peer como verificado apos confirmar SAS
- `/trust <nick>` — Aceita nova chave de um peer (reseta verificacao)
- `/trustlist` — Status de confianca de todos os peers online

**Modelo de confianca para rotacao de chaves**:
- Rotacao E2E autenticada (via canal cifrado, action `key_rotation`) → `autoUpdatePeer()` preserva status `verified`
- Rotacao via servidor (`PEER_KEY_UPDATED`) → NAO atualiza trust store (nao autenticada, potencial MITM)

### 11.3 Secure Memory Wipe — IMPLEMENTADO

**Problema**: Apos decifrar, o plaintext ficava em `Buffer.alloc()` normal, sujeito a swap e GC.

**Solucao**:
- `unpadSecure(padded)`: Copia plaintext para `sodium_malloc()`, wipa buffer padded original
- `encrypt()` em MessageCrypto e DoubleRatchet: `sodium_memzero(padded)` apos cifragem
- `decrypt()` em DoubleRatchet: `sodium_memzero(padded)` em caso de MAC invalido
- `ChatController.#onEncryptedMessage`: `finally { sodium_memzero(plaintext) }` apos processar

**Limitacao**: Strings JS (`toString('utf-8')`, `JSON.parse()`) NAO podem ser wipadas — o V8 GC controla sua vida util. Apenas dados em `Buffer` sao wipados.

### 11.4 Evolucao para P2P (Futuro)

**Fase 1 — Hybrid mode (servidor como signaling)**:
```
1. Clientes descobrem peers via servidor
2. Trocam enderecos IP:porta via servidor
3. Estabelecem conexao WebSocket direta (P2P)
4. Servidor usado apenas para discovery/NAT traversal
```

**Fase 2 — Full P2P com mDNS**:
```
1. Usar mDNS/DNS-SD (pacote: bonjour / mdns) para descoberta na LAN
2. Cada cliente anuncia: "_securelan-chat._tcp" na rede local
3. Clientes encontram peers automaticamente (zero configuracao)
4. Conexao direta sem servidor central
5. Topologia mesh: cada cliente conecta a todos os outros
```

**Fase 3 — P2P com DHT** (para redes maiores):
```
1. Distributed Hash Table para discovery
2. Cada no mantem tabela de roteamento parcial
3. Mensagens podem ser roteadas por multiplos hops
4. Redundancia e tolerancia a falhas
```

### 11.5 Projeto Open-Source Profissional

**Estrutura de repositorio**:
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

**Boas praticas**:
- Semantic versioning (semver)
- Conventional commits
- CI/CD com GitHub Actions
- Dependabot para atualizar dependencias
- CodeQL para analise estatica de seguranca
- Releases assinadas com GPG
- Documentacao no GitHub Pages
- Badges no README (CI, coverage, license, version)
- Issue templates e PR templates
- Security policy com processo de responsible disclosure

### 11.6 Outras Melhorias

| Melhoria | Prioridade | Complexidade |
|----------|------------|-------------|
| Mensagens em grupo com chave de grupo | Alta | Media |
| ~~Envio de arquivos cifrados~~ | ~~Media~~ | ~~Media~~ | ✅ Implementado |
| ~~Indicador de "digitando..."~~ | ~~Baixa~~ | ~~Baixa~~ | ✅ Implementado |
| ~~Notificacoes sonoras~~ | ~~Baixa~~ | ~~Baixa~~ | ✅ Implementado |
| ~~Mensagens offline (queue no servidor)~~ | ~~Media~~ | ~~Alta~~ | ✅ Implementado |
| Multiplos dispositivos por usuario | Baixa | Alta |
| ~~Rotacao automatica de chaves~~ | ~~Alta~~ | ~~Media~~ | ✅ Implementado |
| ~~Padding de mensagens (anti-metadata)~~ | ~~Media~~ | ~~Baixa~~ | ✅ Implementado |
| ~~TLS no WebSocket (wss://)~~ | ~~Media~~ | ~~Baixa~~ | ✅ Implementado |
| Autenticacao do servidor (certificado) | Media | Media |

---

## 12. Glossario

| Termo | Definicao |
|-------|-----------|
| **E2EE** | End-to-End Encryption. Criptografia onde apenas os endpoints (remetente e destinatario) podem ler o conteudo. Intermediarios (servidores) nao tem acesso. |
| **Curve25519** | Curva eliptica projetada por Daniel J. Bernstein. Oferece 128 bits de seguranca com chaves de 32 bytes. Base do X25519 (key exchange). |
| **X25519** | Protocolo de troca de chaves (Diffie-Hellman) baseado em Curve25519. Duas partes com chaves diferentes chegam a um segredo compartilhado. |
| **XSalsa20** | Stream cipher (cifra de fluxo). Variante do Salsa20 com nonce estendido de 24 bytes (vs 8 do Salsa20 original). Projetado por DJB. |
| **Poly1305** | Message Authentication Code (MAC). Gera um tag de 16 bytes que prova que a mensagem nao foi alterada. Combinado com XSalsa20 forma o `crypto_box`. |
| **AEAD** | Authenticated Encryption with Associated Data. Cifra que garante simultaneamente confidencialidade (ninguem le) e integridade (ninguem altera). |
| **Nonce** | Number Used Once. Valor unico usado em cada operacao de cifragem. Se repetido com a mesma chave, a seguranca e comprometida. |
| **PFS** | Perfect Forward Secrecy. Propriedade onde o comprometimento de chaves de longo prazo nao afeta sessoes passadas. |
| **DH** | Diffie-Hellman. Protocolo que permite duas partes estabelecerem um segredo compartilhado sobre um canal inseguro. |
| **MAC** | Message Authentication Code. Funcao que produz um tag verificavel que garante integridade e autenticidade de uma mensagem. |
| **Fingerprint** | Hash curto de uma chave publica, usado para verificacao humana de identidade. |
| **Relay** | Servidor que retransmite dados sem interpretar o conteudo. |
| **Handshake** | Processo de estabelecimento de conexao segura entre duas partes, incluindo troca de chaves e verificacao de identidade. |
| **Side-channel attack** | Ataque que explora informacoes vazadas pela implementacao (tempo de execucao, consumo de energia, cache) em vez de atacar o algoritmo matematicamente. |
| **sodium_malloc** | Funcao da libsodium que aloca memoria protegida: nao vai para swap, e zerada ao ser liberada, protegida contra leitura por outros processos. |
| **Double Ratchet** | Algoritmo usado pelo Signal que combina DH ratchet com KDF chain para garantir PFS por mensagem. |
| **TOFU** | Trust On First Use. Modelo de confianca onde a chave publica de um peer e aceita na primeira conexao e salva localmente. Mudancas posteriores geram alertas (similar ao SSH known_hosts). |
| **SAS** | Short Authentication String. Codigo curto (6 digitos) derivado das chaves publicas de ambos os lados, usado para verificacao de identidade fora-de-banda. |
| **BLAKE2b** | Funcao hash criptografica rapida e segura. Usada como KDF no Double Ratchet e para computar SAS. Suporta keyed hashing (MAC). |
| **mDNS** | Multicast DNS. Protocolo para resolucao de nomes em redes locais sem servidor DNS central. Usado para discovery de servicos (como Bonjour da Apple). |
