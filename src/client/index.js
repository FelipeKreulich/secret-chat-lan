import * as readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { SERVER_PORT } from '../shared/constants.js';
import {
  clientBanner,
  clientConnectingBox,
  promptLabel,
  promptDim,
  promptError,
} from '../shared/banner.js';
import { KeyManager } from '../crypto/KeyManager.js';
import { Connection } from './Connection.js';
import { UI } from './UI.js';
import { ChatController } from './ChatController.js';

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

const serverInput = await rl.question(
  promptLabel(`Servidor ${promptDim(`(localhost:${SERVER_PORT})`)}: `),
);
const serverAddr = serverInput.trim() || `localhost:${SERVER_PORT}`;
const wsUrl = serverAddr.startsWith('ws://') ? serverAddr : `ws://${serverAddr}`;

rl.close();

// ── Pre-connect info ────────────────────────────────────────────
// Create a temporary KeyManager to show fingerprint before blessed takes over
const tempKeys = new KeyManager();
const fingerprint = tempKeys.fingerprint;
tempKeys.destroy();

console.log();
clientConnectingBox(wsUrl, fingerprint);

// Small pause so user can see the info before blessed takes over
await new Promise((resolve) => setTimeout(resolve, 1500));

// ── Initialize ──────────────────────────────────────────────────
const connection = new Connection(wsUrl);
const ui = new UI(nickname);
const controller = new ChatController(nickname, connection, ui);

ui.addInfoMessage(`Seu fingerprint: ${controller.fingerprint}`);
ui.addInfoMessage('Use /help para ver comandos disponiveis');

connection.connect();

// ── Graceful shutdown ───────────────────────────────────────────
process.on('SIGINT', () => {
  controller.destroy();
  process.exit(0);
});

process.on('SIGTERM', () => {
  controller.destroy();
  process.exit(0);
});
