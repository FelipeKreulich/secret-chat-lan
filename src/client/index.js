import * as readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import sodium from 'sodium-native';
import { SERVER_PORT } from '../shared/constants.js';
import {
  clientBanner,
  clientConnectingBox,
  promptLabel,
  promptDim,
  promptError,
} from '../shared/banner.js';
import { KeyManager } from '../crypto/KeyManager.js';
import { StateManager } from '../crypto/StateManager.js';
import { HistoryStore } from '../crypto/HistoryStore.js';
import { parseInvite } from '../shared/invite.js';
import { Connection } from './Connection.js';
import { UI } from './UI.js';
import { ChatController } from './ChatController.js';
import { PluginManager } from '../shared/PluginManager.js';

// ── Banner ──────────────────────────────────────────────────────
clientBanner();

// ── Prompt setup ────────────────────────────────────────────────
const rl = readline.createInterface({ input: stdin, output: stdout });

let nickname = '';
while (!nickname) {
  const raw = await rl.question(promptLabel(`Nickname ${promptDim('(a-z, 0-9, _, -)')}: `));
  const clean = raw.trim().replace(/[^a-zA-Z0-9_-]/g, '');
  if (clean.length >= 1 && clean.length <= 20) {
    nickname = clean;
  } else {
    console.log(promptError('Nickname invalido. Use 1-20 caracteres alfanumericos.'));
  }
}

// ── State restoration ────────────────────────────────────────────
const stateManager = new StateManager();
let restoredState = null;

if (stateManager.hasState()) {
  const passphrase = await rl.question(
    promptLabel(`Passphrase para restaurar sessao ${promptDim('(Enter para pular)')}: `),
  );
  if (passphrase.trim()) {
    restoredState = stateManager.loadState(passphrase.trim());
    if (restoredState) {
      restoredState.passphrase = passphrase.trim();
      console.log(promptLabel('Sessao anterior restaurada com sucesso!'));
    } else {
      console.log(promptError('Passphrase incorreta ou estado corrompido. Nova sessao.'));
    }
  }
} else {
  const passphrase = await rl.question(
    promptLabel(`Passphrase para proteger sessao ${promptDim('(Enter para pular)')}: `),
  );
  if (passphrase.trim()) {
    const confirm = await rl.question(promptLabel('Confirme a passphrase: '));
    if (confirm.trim() === passphrase.trim()) {
      restoredState = { passphrase: passphrase.trim() };
    } else {
      console.log(
        promptError('As passphrases nao conferem — sessao nao sera protegida nesta vez.'),
      );
    }
  }
}

const serverInput = await rl.question(
  promptLabel(`Servidor ${promptDim(`(localhost:${SERVER_PORT} ou convite ciphermesh://)`)}: `),
);
const serverAddr = serverInput.trim() || `localhost:${SERVER_PORT}`;

let wsUrl;
let inviteRoom = null;
const invite = parseInvite(serverAddr);
if (invite) {
  wsUrl = invite.wsUrl;
  inviteRoom = invite.room !== 'general' ? invite.room : null;
} else {
  wsUrl =
    serverAddr.startsWith('ws://') || serverAddr.startsWith('wss://')
      ? serverAddr
      : `wss://${serverAddr}`;
}

rl.close();

// ── Encrypted local history (opt-in, needs passphrase) ─────────
let historyStore = null;
if (restoredState?.passphrase) {
  historyStore = new HistoryStore();
  if (!historyStore.open(restoredState.passphrase)) {
    console.log(
      promptError('Historico: passphrase nao confere — historico desativado nesta sessao'),
    );
    historyStore = null;
  }
}

// ── Pre-connect info ────────────────────────────────────────────
// Create a temporary KeyManager to show fingerprint before blessed takes over
const tempKeys = restoredState?.keyManager
  ? KeyManager.deserialize(restoredState.keyManager)
  : new KeyManager();
const fingerprint = tempKeys.fingerprint;
tempKeys.destroy();

console.log();
clientConnectingBox(wsUrl, fingerprint);

// Small pause so user can see the info before blessed takes over
await new Promise((resolve) => setTimeout(resolve, 1500));

// ── Load plugins ────────────────────────────────────────────────
const pluginManager = new PluginManager();
await pluginManager.loadAll();

// ── Initialize ──────────────────────────────────────────────────

const connection = new Connection(wsUrl);
const ui = new UI(nickname);
const controller = new ChatController(
  nickname,
  connection,
  ui,
  restoredState,
  pluginManager,
  inviteRoom,
  historyStore,
);

ui.addInfoMessage(`Seu fingerprint: ${controller.fingerprint}`);
ui.addInfoMessage('Use /help para ver comandos disponiveis');

if (restoredState?.handshake) {
  ui.addSystemMessage('Sessao anterior restaurada — ratchets preservados');
}

connection.connect();

// ── Graceful shutdown ───────────────────────────────────────────
function shutdown() {
  const passphrase = controller.passphrase;
  if (passphrase) {
    try {
      const state = controller.serializeState();
      const { kek, salt, opslimit, memlimit } = stateManager.deriveKEK(passphrase);
      stateManager.saveState(state, kek, salt, opslimit, memlimit);
      sodium.sodium_memzero(kek);
    } catch {
      // Best effort — don't block shutdown
    }
  }
  controller.destroy();
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
