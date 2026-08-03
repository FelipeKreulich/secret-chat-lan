# Terms of Use — CipherMesh Hub

**Last updated:** 3 August 2026 · [Versão em português abaixo](#termos-de-uso--ciphermesh-hub-1)

## 1. What this service is

**CipherMesh Hub** is a public **relay** for [CipherMesh](https://github.com/FelipeKreulich/secret-chat-lan),
an end-to-end encrypted terminal chat. It forwards encrypted payloads between participants.

| | |
|---|---|
| Operator | Felipe Kreulich |
| Address | `ciphermesh.de` |
| Hosted by | Hetzner Online GmbH — Falkenstein, Germany |
| Abuse contact | contato.felipe.kreulich@gmail.com |
| Cost | Free. There is no account, no payment, and no registration. |

Connecting to the service means you accept these terms. If you do not accept them, do not connect.

## 2. What the operator can and cannot see

Messages are encrypted on your device and decrypted on your correspondent's device. **The operator
cannot read, alter, or recover the content of any message** — and neither could someone who
compromised the server. This is a property of the software, which is open source and auditable, not
a promise of good behaviour.

**What the server necessarily handles** while your connection is open:

- your network address;
- the nickname you chose and your public key;
- which rooms you are in, and the size and timing of the traffic you generate.

**What the server does not have:**

- message contents — it never receives them in readable form;
- message history — rooms exist only while someone is inside and disappear, with everything said
  in them, when the last participant leaves;
- private-room passwords — these never reach the server in any form.

**Operational logs** record connections, room events and errors — never content. They are kept for
**at most 7 days**, for abuse handling and debugging, and then deleted.

## 3. Your responsibilities

You agree not to use the service to:

- do anything unlawful under Portuguese or European Union law;
- harass, threaten, or endanger anyone;
- distribute malware, or material depicting the sexual abuse of minors;
- attack the service or third parties through it — flooding, exploiting, or circumventing the
  connection and rate limits.

You are solely responsible for what you send. Because of how the encryption works, **the operator
has no way to detect a violation by reading messages**, and does not attempt to.

## 4. What the operator can actually do

The available measures are limited to infrastructure, and they are blunt:

- refuse connections from a network address;
- change or reduce the connection, room, and message-rate limits;
- take the service offline, wholly or partly, at any time and without notice.

The operator **cannot** remove a specific message, moderate a conversation, hand over content that
does not exist in readable form, or verify who anyone is. Requests that assume otherwise cannot be
fulfilled — not as a matter of policy, but as a matter of fact.

Within a room, whoever created it can remove or mute participants (`/kick`, `/mute`, `/ban`), but
only inside that room and only while it exists.

## 5. Data protection (GDPR)

The operator is established in Portugal and the server is in Germany, so the GDPR applies to the
limited data described in section 2.

- **Legal basis:** legitimate interest in operating a communications service and protecting it
  from abuse.
- **Data processed:** network address, nickname, public key, and connection metadata.
- **Retention:** connection data exists only while the connection is open; operational logs for at
  most 7 days.
- **Your rights:** access, rectification, erasure, restriction and objection. Write to the abuse
  contact above. Note that, because there are no accounts and no message storage, in practice there
  is nothing to export or erase after your connection closes.
- **Transfers:** none. Data is not shared with third parties, sold, or used for advertising or
  profiling.

## 6. Availability

The service is provided **as is**, with no guarantee of availability, integrity, or data
preservation. It may be interrupted, restarted, or discontinued at any time. It is run as a
personal, non-commercial project. **Do not rely on it as your only channel for anything that
matters.**

## 7. Liability

To the extent permitted by law, the operator is not liable for damages arising from the use or
unavailability of the service, nor for the content users exchange through it — content to which
the operator has no access.

## 8. Reporting abuse

Write to **contato.felipe.kreulich@gmail.com**, including the service address, when it happened,
and what you observed.

**Do not send message content expecting it to be verified: there is no way to do so.** Useful
reports concern network behaviour (flooding, scanning, attacks) or conduct you witnessed as a
participant in a room.

## 9. Changes

These terms may change. The current version is always at
<https://github.com/FelipeKreulich/secret-chat-lan/blob/master/TERMS.md>, with the date at the top.
Substantial changes are announced in the server notice shown when you connect.

---
---

# Termos de Uso — CipherMesh Hub

**Última atualização:** 3 de agosto de 2026 · [English version above](#terms-of-use--ciphermesh-hub)

## 1. O que é este serviço

O **CipherMesh Hub** é um **relay** público do [CipherMesh](https://github.com/FelipeKreulich/secret-chat-lan),
um chat de terminal com criptografia ponta-a-ponta. Ele encaminha payloads cifrados entre os
participantes.

| | |
|---|---|
| Operador | Felipe Kreulich |
| Endereço | `ciphermesh.de` |
| Hospedagem | Hetzner Online GmbH — Falkenstein, Alemanha |
| Contato de abuso | contato.felipe.kreulich@gmail.com |
| Custo | Gratuito. Não há conta, pagamento nem cadastro. |

Conectar-se ao serviço significa aceitar estes termos. Se não os aceita, não conecte.

## 2. O que o operador consegue e não consegue ver

As mensagens são cifradas no seu dispositivo e decifradas no dispositivo de quem conversa com
você. **O operador não consegue ler, alterar nem recuperar o conteúdo de nenhuma mensagem** — e
quem comprometesse o servidor também não. Isso é uma propriedade do software, que é aberto e
auditável, não uma promessa de boa conduta.

**O que o servidor necessariamente manipula** enquanto sua conexão existe:

- seu endereço de rede;
- o apelido que você escolheu e sua chave pública;
- em quais salas você está, e o tamanho e o horário do tráfego que você gera.

**O que o servidor não tem:**

- conteúdo das mensagens — ele nunca o recebe em forma legível;
- histórico — salas existem apenas enquanto alguém está dentro e desaparecem, com tudo o que foi
  dito nelas, quando a última pessoa sai;
- senhas de salas privadas — elas nunca chegam ao servidor, de forma alguma.

**Logs operacionais** registram conexões, eventos de sala e erros — nunca conteúdo. São mantidos
por **no máximo 7 dias**, para tratar abuso e depurar problemas, e depois apagados.

## 3. Suas responsabilidades

Você concorda em não usar o serviço para:

- praticar qualquer ato ilícito segundo a lei portuguesa ou da União Europeia;
- assediar, ameaçar ou colocar alguém em risco;
- distribuir malware ou material de abuso sexual infantil;
- atacar o serviço ou terceiros através dele — inundar, explorar ou burlar os limites de conexão
  e de taxa.

Você é o único responsável pelo que envia. Pelo modo como a criptografia funciona, **o operador
não tem como detectar uma violação lendo mensagens**, e não tenta.

## 4. O que o operador realmente pode fazer

As medidas disponíveis limitam-se à infraestrutura, e são grosseiras:

- recusar conexões de um endereço de rede;
- alterar ou reduzir os limites de conexão, de salas e de taxa de mensagens;
- tirar o serviço do ar, no todo ou em parte, a qualquer momento e sem aviso.

O operador **não pode** remover uma mensagem específica, moderar uma conversa, entregar conteúdo
que não existe em forma legível, nem verificar quem alguém é. Pedidos que pressuponham o contrário
não têm como ser atendidos — não por política, mas por impossibilidade.

Dentro de uma sala, quem a criou pode remover ou silenciar participantes (`/kick`, `/mute`,
`/ban`), mas apenas dentro daquela sala e enquanto ela existir.

## 5. Proteção de dados (RGPD)

O operador está estabelecido em Portugal e o servidor fica na Alemanha, portanto o RGPD aplica-se
aos dados limitados descritos na secção 2.

- **Base legal:** interesse legítimo em operar um serviço de comunicação e protegê-lo de abuso.
- **Dados tratados:** endereço de rede, apelido, chave pública e metadados de conexão.
- **Conservação:** os dados de conexão existem apenas enquanto a conexão está aberta; os logs
  operacionais, no máximo 7 dias.
- **Os seus direitos:** acesso, retificação, apagamento, limitação e oposição. Escreva para o
  contato de abuso acima. Note que, como não há contas nem armazenamento de mensagens, na prática
  não existe nada para exportar ou apagar depois que a sua conexão termina.
- **Transferências:** nenhuma. Os dados não são partilhados com terceiros, vendidos, nem usados
  para publicidade ou definição de perfis.

## 6. Disponibilidade

O serviço é fornecido **como está**, sem garantia de disponibilidade, integridade ou preservação
de dados. Pode ser interrompido, reiniciado ou encerrado a qualquer momento. É mantido como um
projeto pessoal e não comercial. **Não o utilize como seu único canal para nada que importe.**

## 7. Responsabilidade

Na medida permitida por lei, o operador não responde por danos decorrentes do uso ou da
indisponibilidade do serviço, nem pelo conteúdo que os utilizadores trocam por meio dele —
conteúdo ao qual o operador não tem acesso.

## 8. Denúncias de abuso

Escreva para **contato.felipe.kreulich@gmail.com**, indicando o endereço do serviço, quando
aconteceu e o que observou.

**Não envie conteúdo de mensagens esperando que seja verificado: não há como.** Relatos úteis
tratam de comportamento de rede (inundação, varredura, ataques) ou de conduta que você presenciou
como participante de uma sala.

## 9. Alterações

Estes termos podem mudar. A versão vigente está sempre em
<https://github.com/FelipeKreulich/secret-chat-lan/blob/master/TERMS.md>, com a data no topo.
Alterações relevantes são anunciadas no aviso do servidor exibido ao conectar.
