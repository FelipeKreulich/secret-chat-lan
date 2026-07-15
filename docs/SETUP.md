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

O servidor vai rodar na porta `3600` (com TLS/`wss://` por padrao) e ficar acessivel para toda a rede local — e, se voce usar Tailscale, tambem pela internet (ver secao abaixo).

### `ADVERTISE_IP` — mostrar o IP certo no banner (Docker)

Dentro do Docker, o container roda na bridge do Docker (`172.x`) e **nao enxerga as interfaces do host** (nem a LAN, nem a `tailscale0`). Por isso, em Docker, o banner nao consegue descobrir sozinho qual endereco anunciar.

A variavel `ADVERTISE_IP` resolve isso — passe um ou mais IPs do host (separados por virgula) e o banner passa a exibir as URLs corretas. Crie um arquivo `.env` (ja no `.gitignore`) ao lado do `docker-compose.yml`:

```bash
# .env — IPs do host anunciados no banner (separados por virgula)
#   LAN:       ipconfig getifaddr en0   (macOS)  /  hostname -I  (Linux)
#   Tailscale: tailscale ip -4
ADVERTISE_IP=192.168.1.7,100.73.206.23
```

O banner entao mostra:

```
╭─────────────  SERVER  ──────────────╮
│   Porta    3600                     │
│   Local    wss://192.168.1.7:3600   │   ← rede local
│   Internet wss://100.73.206.23:3600 │   ← Tailscale (fora da rede)
│   Status   ● Online                 │
╰─────────────────────────────────────╯
```

> `ADVERTISE_IP` so muda **o que o banner exibe** — nao restringe quem conecta. O mapeamento `3600:3600` do compose ja expoe a porta em **todas** as interfaces do host ao mesmo tempo, entao o servidor responde na LAN e no Tailscale independentemente disso.

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

Quando o servidor inicia, ele mostra os enderecos disponiveis:

```
╭────────────────  SERVER  ────────────────╮
│   Porta    3600                          │
│   Local    wss://192.168.1.142:3600      │
│   Status   ● Online                      │
╰──────────────────────────────────────────╯
```

O amigo digita `192.168.1.142:3600` quando o cliente perguntar o servidor (nao precisa digitar `wss://` — o cliente completa sozinho e aceita o certificado auto-assinado automaticamente).

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

O modo LAN so funciona com todo mundo na **mesma rede**. Para conversar com alguem em **outra rede** (outra casa, outra cidade, outro pais), a forma mais simples e o [Tailscale](https://tailscale.com): uma VPN mesh gratuita (baseada no WireGuard) que cria uma "LAN virtual" — a **tailnet** — entre as suas maquinas. Funciona mesmo atras de CGNAT e NAT duplo, **sem abrir porta no roteador**.

A criptografia do chat continua **ponta-a-ponta** — o Tailscale e so o transporte. Mesmo que a rede Tailscale fosse comprometida, o conteudo das mensagens segue protegido pelo E2EE (e ainda ha verificacao de identidade com `/verify`).

### Conceito que confunde todo mundo: o IP e da MAQUINA, nao algo que voce escolhe

Cada dispositivo na tailnet ganha um **IP fixo proprio** na faixa `100.x` (CGNAT `100.64.0.0/10`) — essa e a **identidade daquela maquina** na rede. Consequencias:

- O servidor e alcancavel pelo IP Tailscale da **maquina que roda o servidor**.
- Voce **nao "escolhe"** um IP `100.x` para o servidor. Se quer que o servidor seja `100.a.b.c`, precisa rodar o servidor **naquela maquina especifica**.
- `tailscale status` numa maquina lista os IPs 100.x de **cada** dispositivo (o seu e os dos outros). O do seu servidor e o da maquina onde o `docker compose up` / `npm run server` roda.

### 1. Instalar o Tailscale (nos dois lados)

```bash
# Linux
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# macOS  (app de menu; ou via Homebrew)
brew install --cask tailscale     # depois abra o app e faca login

# Windows
winget install tailscale.tailscale
```

O `tailscale up` (ou o app) abre uma URL no navegador para fazer login (Google, GitHub, Microsoft, e-mail...).

> **macOS:** o `tailscale` da linha de comando muitas vezes **nao esta no PATH**. Se `tailscale ip -4` der "command not found", use o binario dentro do app:
> ```bash
> /Applications/Tailscale.app/Contents/MacOS/Tailscale ip -4
> ```

### 2. Colocar as duas maquinas na mesma tailnet

Contas separadas **nao se enxergam** por padrao. Escolha uma opcao:

- **Convidar o outro para a sua tailnet**: [admin console](https://login.tailscale.com/admin/users) → **Users** → **Invite users**. O plano gratuito (Personal) aceita ate ~3 usuarios e 100 dispositivos.
- **Compartilhar so a maquina do servidor**: admin console → **Machines** → `...` na maquina do servidor → **Share** — o outro aceita o link e passa a enxergar **so** essa maquina (bom para privacidade).

Confirme que os dois aparecem **online** (bolinha verde) em `tailscale status` ou no admin console. Se o peer estiver `offline`, ele **nao** vai conseguir conectar ate abrir o Tailscale.

### 3. Descobrir o IP Tailscale do servidor

Na maquina que **roda o servidor**:

```bash
tailscale ip -4
# ex: 100.73.206.23
```

Esse IP tambem aparece no banner do servidor com o rotulo `Internet` (fora do Docker, o banner detecta a interface Tailscale sozinho; **dentro do Docker**, defina `ADVERTISE_IP` — ver a secao do Docker acima).

### 4. O servidor responde na LAN E no Tailscale ao mesmo tempo

O servidor faz `bind` em `0.0.0.0:3600`, ou seja, escuta em **todas** as interfaces da maquina simultaneamente. Voce **nao precisa** reiniciar nem escolher a rede — o mesmo servidor e alcancavel por:

- `wss://<IP-LAN>:3600` — quem esta na **mesma rede local** (ex: `wss://192.168.1.7:3600`)
- `wss://<IP-Tailscale>:3600` — quem esta **fora da rede**, na tailnet (ex: `wss://100.73.206.23:3600`)

### 5. Qual endereco passar para quem

| Pessoa | Situacao | Endereco que voce passa |
|---|---|---|
| Amigo em **outra rede**, com Tailscale | na sua tailnet | `<IP-Tailscale>:3600` (ex: `100.73.206.23:3600`) |
| Colega na **mesma rede**, sem Tailscale | mesma LAN | `<IP-LAN>:3600` (ex: `192.168.1.7:3600`) |
| Voce mesmo, na maquina do servidor | localhost | `localhost:3600` |

> Um peer **sem** Tailscale, mas na sua rede local, **nao precisa** de Tailscale — ele conecta direto pelo IP da LAN. Tailscale so e necessario para quem esta **fora** da rede.

### 6. Conectar

Quem hospeda sobe o servidor normalmente (`docker compose up -d` ou `npm run server`). O outro roda `npm run client` e, quando pedir o servidor, informa o IP + porta:

```
Servidor: 100.73.206.23:3600
```

Nao precisa digitar `wss://` — o cliente completa sozinho e **aceita o certificado auto-assinado automaticamente**. Na primeira conexao o cliente **fixa o fingerprint do certificado** (TOFU); se ele mudar depois, o chat exibe um alerta.

**Atalho — convite com QR:** quem hospeda pode rodar, dentro do chat:

```
/invite 100.73.206.23:3600
```

Sai uma string `ciphermesh://...` **com QR code** que o outro cola direto no prompt `Servidor` (ja entra na sala do convite).

### Troubleshooting Tailscale

- **`tailscale status`** — lista as maquinas da tailnet e se estao online. Peer `offline` nao conecta ate abrir o Tailscale.
- **`tailscale ping 100.x.y.z`** — testa a conectividade direta ate o peer (deve responder via DERP ou direto).
- **Firewall do host** — libere a porta `3600` de entrada. No macOS: Ajustes → Rede → Firewall. No Windows: `netsh advfirewall firewall add rule name="CipherMesh" dir=in action=allow protocol=TCP localport=3600`.
- **Docker** — o mapeamento `3600:3600` do compose ja expoe a porta em todas as interfaces do host (incluindo `tailscale0`), entao a conexao pela tailnet funciona; o `ADVERTISE_IP` so ajuda o **banner** a mostrar o IP certo.
- **"Conecta e cai" / so LAN funciona** — confirme que os dois estao na **mesma tailnet** (nao so instalados) e online.
- **Wi-Fi de empresa/hotel com _client isolation_ (AP isolation)** — dispositivos na mesma rede nao se enxergam; nesse caso o Tailscale (ou um cabo/outro AP) resolve mesmo "estando na mesma rede".
- **Certificado auto-assinado** — normal; o cliente aceita sozinho e usa o E2EE + `/verify` como protecao real de identidade.

---

## Comandos no chat

Rode `/help` no chat para a **lista completa**. Os principais:

| Comando | Descricao |
|---------|-----------|
| `/help` | Lista completa de comandos |
| `/users` | Usuarios online |
| `/msg <nick> <texto>` | Mensagem privada (DM) |
| `/invite <ip>:<porta>` | Gera convite `ciphermesh://` + QR |
| `/fingerprint [nick]` | Fingerprint + randomart da chave |
| `/verify <nick>` | Codigo SAS + QR + randomart para verificar identidade |
| `/verify-confirm <nick>` | Marca o peer como verificado |
| `/file <caminho>` | Envia arquivo (o outro aceita com `/accept`) |
| `/accept` · `/reject` | Aceita / recusa um arquivo oferecido |
| `/img [caminho]` | Renderiza a ultima imagem recebida em alta resolucao (kitty/iTerm2) |
| `/join <sala>` · `/rooms` · `/room` | Salas (canais) |
| `/backup [caminho]` | Backup cifrado da identidade + confianca |
| `/deniable [on\|off]` | Modo deniable (cripto simetrica) |
| `/ephemeral <tempo>` | Mensagens efemeras |
| `/retention <tempo>` | Purga historico local antigo |
| `/nick <novo>` | Troca de apelido (antes de entrar) |
| `/clear` · `/quit` | Limpa o chat / sai |

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
