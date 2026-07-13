# CipherMesh — Setup e Deploy

Guia completo para rodar o servidor e conectar clientes na rede local.

---

## Opcao 1: Docker (recomendado para o servidor)

### Requisitos

- [Docker](https://docs.docker.com/get-docker/) instalado

### Subir o servidor

```bash
# Build + start em background
npm run docker:up

# Ou manualmente
docker compose up -d --build
```

O servidor vai rodar na porta `3600` e ficar acessivel para toda a rede local.

### Ver logs do servidor

```bash
npm run docker:logs

# Ou
docker compose logs -f
```

### Parar o servidor

```bash
npm run docker:down
```

### Verificar se esta rodando

```bash
docker ps
# Deve mostrar: ciphermesh-server
```

---

## Opcao 2: Node.js direto

### Requisitos

- Node.js >= 20

### Iniciar servidor

```bash
npm run server
```

O servidor imprime todos os IPs da LAN e a porta.

---

## Conectar como cliente

### Requisitos do cliente

- Node.js >= 20
- Git (para clonar o repo)

### Passo a passo (para voce ou seu amigo)

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

O cliente vai pedir:
1. **Nickname** — seu nome no chat
2. **Servidor** — IP de quem esta rodando o servidor (ex: `192.168.1.142:3600`)

### Como saber o IP do servidor?

Quando o servidor inicia, ele mostra todos os IPs disponiveis:

```
╭────────────────  SERVER  ────────────────╮
│   Porta    3600                          │
│   Wi-Fi    ws://192.168.1.142:3600       │
│   Status   ● Online                      │
╰──────────────────────────────────────────╯
```

O amigo digita `192.168.1.142:3600` quando o cliente perguntar o servidor.

---

## Cenario tipico

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

1. Tu sobe o servidor (Docker ou Node)
2. Tu abre outro terminal e roda `npm run client` tambem
3. Teu amigo clona o repo, instala, e roda `npm run client`
4. Ambos escolhem nicknames e conectam no teu IP
5. Chat E2EE funcionando

---

## Conectando pela Internet (Tailscale)

O modo LAN so funciona com todo mundo na mesma rede. Para conversar com alguem em outra rede (outra casa, outra cidade), a forma mais simples e o [Tailscale](https://tailscale.com) — uma VPN gratuita que cria uma "LAN virtual" entre as maquinas. Funciona mesmo atras de CGNAT, sem abrir porta no roteador.

A criptografia do chat continua ponta-a-ponta — o Tailscale e so o transporte. Mesmo que a rede Tailscale fosse comprometida, o conteudo das mensagens segue protegido pelo E2EE.

### 1. Instalar o Tailscale (nos dois lados)

```bash
# Linux
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Mac
brew install --cask tailscale

# Windows
winget install tailscale.tailscale
```

O `tailscale up` abre uma URL no navegador para fazer login (Google, GitHub, etc).

### 2. Colocar as duas maquinas na mesma tailnet

Contas separadas nao se enxergam por padrao. Escolha uma opcao:

- **Convidar o amigo para sua tailnet**: [admin console](https://login.tailscale.com/admin/users) → Users → Invite users. O plano gratuito aceita ate 3 usuarios.
- **Compartilhar so a maquina do servidor**: admin console → Machines → `...` na maquina → Share — o amigo aceita o link e passa a enxergar so essa maquina.

### 3. Descobrir o IP Tailscale do servidor

```bash
tailscale ip -4
# ex: 100.101.102.103
```

Esse IP tambem aparece no banner do servidor com o rotulo `Internet` quando ele inicia.

### 4. Conectar

Quem hospeda sobe o servidor normalmente (`npm run server` ou Docker). O amigo roda `npm run client` e informa o IP Tailscale:

```
Servidor: 100.101.102.103:3600
```

Pronto — mesmo chat, mesma criptografia, so muda o caminho da rede.

Dica: quem hospeda pode rodar `/invite 100.101.102.103:3600` dentro do chat — sai uma string `ciphermesh://...` com QR code que o amigo cola direto no prompt `Servidor` (e ja entra na sala do convite).

### Troubleshooting Tailscale

- `tailscale status` — lista as maquinas da tailnet e mostra se estao online
- `tailscale ping 100.x.y.z` — testa a conectividade direta entre os peers
- Se conectar mas cair direto, verifica se o firewall libera a porta 3600 na interface `tailscale0`
- Com Docker, o mapeamento `3600:3600` do compose ja expoe a porta para a interface Tailscale do host

---

## Comandos no chat

| Comando | Descricao |
|---------|-----------|
| `/help` | Lista de comandos |
| `/users` | Mostra usuarios online |
| `/fingerprint` | Mostra seu fingerprint |
| `/fingerprint <nick>` | Fingerprint de outro usuario |
| `/clear` | Limpa o chat |
| `/quit` | Sai do chat |

---

## Troubleshooting

### "Conexao recusada" / nao conecta

- Verifica se o servidor esta rodando: `docker ps` ou checa o terminal
- Verifica se estao na **mesma rede Wi-Fi/LAN** (ou na mesma tailnet, no modo internet)
- Verifica se o **firewall** nao esta bloqueando a porta 3600
  - Windows: `Configuracoes > Firewall > Permitir app > Node.js`
  - Ou: `netsh advfirewall firewall add rule name="CipherMesh" dir=in action=allow protocol=TCP localport=3600`
- Testa se a porta responde: `curl ws://IP:3600` ou abre `http://IP:3600` no browser (vai dar erro, mas se conectar a porta esta aberta)

### "npm install" falha no sodium-native

O `sodium-native` precisa compilar codigo C. Requisitos:
- **Windows**: `npm install --global windows-build-tools` ou instalar Visual Studio Build Tools
- **Mac**: `xcode-select --install`
- **Linux**: `sudo apt install python3 make g++`

### Docker demora no build

Normal na primeira vez — precisa compilar o sodium-native dentro do container. Builds subsequentes usam cache e sao rapidos.
