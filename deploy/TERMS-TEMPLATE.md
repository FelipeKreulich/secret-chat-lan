# Terms of Use — template for a public CipherMesh relay

**This is a template, not legal advice.** Replace every `[bracket]`, read it
end to end, and have a lawyer look at it if the relay will carry real traffic
or you are in a jurisdiction with data-retention duties. It is written to be
honest about a service whose defining property is that **the operator cannot
read what passes through it**.

A Portuguese version follows the English one. Publish the language your users
actually speak — or both.

---

## English

### Terms of Use — [service name]

Last updated: [date]

#### 1. What this service is

[service name] is a **relay** for CipherMesh, an end-to-end encrypted chat.
It forwards encrypted payloads between participants. It is operated by
[your name or entity] and reachable at [address].

Using the service means you accept these terms. If you do not, do not connect.

#### 2. What the operator can and cannot see

Messages are encrypted on your device and decrypted on your correspondent's.
**The operator cannot read, alter, or recover the content of any message**,
and neither can anyone who compromises the server. This is a property of the
software, not a promise of good behaviour.

What the server does necessarily handle, while a connection is open:

- your network address;
- the nickname you chose and your public key;
- which rooms you are in, and the size and timing of the traffic you generate.

What the server does **not** keep: message contents (it never has them in
readable form), and no message history — rooms exist only while someone is
inside them and vanish, with their contents, when the last participant leaves.
Private-room passwords are never sent to the server at all.

Operational logs may record connections and errors, without content, and are
kept for at most [e.g. 7 days] for abuse handling and debugging.

#### 3. Your responsibilities

You agree not to use the service to:

- do anything illegal under the law of [jurisdiction];
- harass, threaten, or endanger anyone;
- distribute malware, or material depicting the sexual abuse of minors;
- attack the service or others through it — flooding, exploiting, or
  circumventing the connection and rate limits.

You are responsible for what you send. Because of how the encryption works,
**the operator has no way to detect a violation by reading messages** and does
not attempt to.

#### 4. What the operator can actually do

The available measures are limited to infrastructure, and they are blunt:

- refuse connections from an address;
- change or reduce the connection, room, and rate limits;
- take the service offline, wholly or partly, at any time and without notice.

The operator **cannot** remove a specific message, moderate a conversation,
hand over content that does not exist in readable form, or verify who anyone
is. Requests that assume otherwise cannot be fulfilled — not as policy, but
as fact.

#### 5. Availability

The service is offered **as is**, with no guarantee of availability, integrity,
or data preservation. It may be interrupted, reset, or discontinued at any
time. Do not use it as your only channel for anything that matters.

#### 6. Liability

To the extent permitted by law, the operator is not liable for damages arising
from the use or unavailability of the service, nor for the content that users
exchange through it — which the operator does not have access to.

#### 7. Reporting abuse

Write to [abuse contact]. Include the address of the service, when it happened
and what you observed. **Do not send message content expecting the operator to
verify it: there is no way to.** Useful reports are about network behaviour
(flooding, scanning, attacks) or about conduct you witnessed as a participant.

#### 8. Changes

These terms may change. The current version is always at [terms URL], with the
date at the top. Substantial changes will be announced in the server notice
(MOTD) when practical.

---

## Português

### Termos de Uso — [nome do serviço]

Última atualização: [data]

#### 1. O que é este serviço

[nome do serviço] é um **relay** do CipherMesh, um chat com criptografia
ponta-a-ponta. Ele encaminha payloads cifrados entre os participantes. É
operado por [seu nome ou entidade] e fica em [endereço].

Usar o serviço significa aceitar estes termos. Se não aceita, não conecte.

#### 2. O que o operador consegue e não consegue ver

As mensagens são cifradas no seu dispositivo e decifradas no dispositivo de
quem conversa com você. **O operador não consegue ler, alterar nem recuperar o
conteúdo de nenhuma mensagem**, e quem comprometer o servidor também não.
Isso é uma propriedade do software, não uma promessa de boa conduta.

O que o servidor necessariamente manipula enquanto a conexão existe:

- seu endereço de rede;
- o apelido que você escolheu e sua chave pública;
- em quais salas você está, e o tamanho e o horário do tráfego que você gera.

O que o servidor **não** guarda: conteúdo de mensagens (ele nunca o tem em
forma legível) e nenhum histórico — salas existem só enquanto alguém está
dentro e desaparecem, com o que foi dito, quando a última pessoa sai. Senhas
de salas privadas nunca chegam ao servidor.

Logs operacionais podem registrar conexões e erros, sem conteúdo, e são
mantidos por no máximo [ex.: 7 dias] para tratar abuso e depurar problemas.

#### 3. Suas responsabilidades

Você concorda em não usar o serviço para:

- praticar qualquer ato ilegal segundo a lei de [jurisdição];
- assediar, ameaçar ou colocar alguém em risco;
- distribuir malware ou material de abuso sexual infantil;
- atacar o serviço ou terceiros através dele — inundar, explorar ou burlar os
  limites de conexão e de taxa.

Você é responsável pelo que envia. Pelo modo como a criptografia funciona,
**o operador não tem como detectar uma violação lendo mensagens** e não tenta.

#### 4. O que o operador realmente pode fazer

As medidas disponíveis se limitam à infraestrutura, e são grosseiras:

- recusar conexões de um endereço;
- alterar ou reduzir os limites de conexão, de salas e de taxa;
- tirar o serviço do ar, no todo ou em parte, a qualquer momento e sem aviso.

O operador **não pode** remover uma mensagem específica, moderar uma conversa,
entregar conteúdo que não existe em forma legível, nem verificar quem alguém
é. Pedidos que pressuponham o contrário não têm como ser atendidos — não por
política, mas por impossibilidade.

#### 5. Disponibilidade

O serviço é oferecido **como está**, sem garantia de disponibilidade,
integridade ou preservação de dados. Pode ser interrompido, reiniciado ou
encerrado a qualquer momento. Não o use como seu único canal para nada que
importe.

#### 6. Responsabilidade

Na medida permitida por lei, o operador não responde por danos decorrentes do
uso ou da indisponibilidade do serviço, nem pelo conteúdo que os usuários
trocam por meio dele — ao qual o operador não tem acesso.

#### 7. Denúncias de abuso

Escreva para [contato de abuso]. Inclua o endereço do serviço, quando
aconteceu e o que você observou. **Não envie conteúdo de mensagens esperando
que o operador verifique: não há como.** Relatos úteis tratam de comportamento
de rede (inundação, varredura, ataques) ou de conduta que você presenciou como
participante.

#### 8. Alterações

Estes termos podem mudar. A versão vigente está sempre em [URL dos termos],
com a data no topo. Mudanças relevantes serão anunciadas no aviso do servidor
(MOTD) quando for possível.
