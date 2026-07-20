import * as readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { readFileSync } from 'node:fs';
import sodium from 'sodium-native';
import { SERVER_PORT } from '../shared/constants.js';
import {
  animatedBanner,
  bootSequence,
  clientConnectingBox,
  promptLabel,
  promptDim,
  promptError,
} from '../shared/banner.js';
import { KeyManager } from '../crypto/KeyManager.js';
import { StateManager } from '../crypto/StateManager.js';
import { HistoryStore } from '../crypto/HistoryStore.js';
import { parseInvite } from '../shared/invite.js';
import { importBackup } from '../crypto/IdentityBackup.js';
import { questionHidden } from '../shared/prompt.js';
import { loadConfig, startupCommands } from '../shared/config.js';
import { setTheme } from '../shared/themes.js';
import { Connection } from './Connection.js';
import { UI } from './UI.js';
import { ChatController } from './ChatController.js';
import { PluginManager } from '../shared/PluginManager.js';

// ── Banner ──────────────────────────────────────────────────────
await animatedBanner();

// ── Config (optional defaults from ~/.ciphermesh/config.json) ────
const config = loadConfig();
if (config.theme) {
  setTheme(config.theme);
}

// ── Prompt setup ────────────────────────────────────────────────
const rl = readline.createInterface({ input: stdin, output: stdout });

let nickname = '';
while (!nickname) {
  const hint = config.nickname ? `(${config.nickname})` : '(a-z, 0-9, _, -)';
  const raw = await rl.question(promptLabel(`Nickname ${promptDim(hint)}: `));
  const clean = (raw.trim() || config.nickname || '').replace(/[^a-zA-Z0-9_-]/g, '');
  if (clean.length >= 1 && clean.length <= 20) {
    nickname = clean;
  } else {
    console.log(promptError('Invalid nickname. Use 1-20 alphanumeric characters.'));
  }
}

// ── State restoration ────────────────────────────────────────────
const stateManager = new StateManager();
let restoredState = null;

if (stateManager.hasState()) {
  const passphrase = await questionHidden(
    rl,
    promptLabel(`Passphrase to restore session ${promptDim('(Enter to skip)')}: `),
  );
  if (passphrase.trim()) {
    restoredState = stateManager.loadState(passphrase.trim());
    if (restoredState) {
      restoredState.passphrase = passphrase.trim();
      console.log(promptLabel('Previous session restored successfully!'));
    } else {
      console.log(promptError('Incorrect passphrase or corrupted state. Starting a new session.'));
    }
  }
} else {
  const passphrase = await questionHidden(
    rl,
    promptLabel(`Passphrase to protect session ${promptDim('(Enter to skip)')}: `),
  );
  if (passphrase.trim()) {
    const confirm = await questionHidden(rl, promptLabel('Confirm the passphrase: '));
    if (confirm.trim() === passphrase.trim()) {
      restoredState = { passphrase: passphrase.trim() };
    } else {
      console.log(
        promptError('Passphrases do not match — session will not be protected this time.'),
      );
    }
  }
}

// Offer to restore identity + trust from an encrypted backup (only when there
// is no session to restore).
if (!restoredState?.keyManager) {
  const backupPath = await rl.question(
    promptLabel(`Restore identity from a backup? ${promptDim('(path or Enter)')}: `),
  );
  if (backupPath.trim()) {
    try {
      const raw = readFileSync(backupPath.trim(), 'utf-8');
      const pass = await questionHidden(rl, promptLabel('Backup passphrase: '));
      const data = importBackup(raw, pass.trim());
      if (data?.identity) {
        restoredState = {
          ...(restoredState || {}),
          keyManager: data.identity,
          trust: data.trust,
          passphrase: pass.trim(),
        };
        console.log(promptLabel('Identity + trust restored from backup!'));
      } else {
        console.log(promptError('Invalid backup or incorrect passphrase.'));
      }
    } catch (e) {
      console.log(promptError(`Could not read the backup: ${e.message}`));
    }
  }
}

const defaultServer = config.server || `localhost:${SERVER_PORT}`;
const serverInput = await rl.question(
  promptLabel(`Server ${promptDim(`(${defaultServer} or ciphermesh:// invite)`)}: `),
);
const serverAddr = serverInput.trim() || defaultServer;

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
    console.log(promptError('History: passphrase mismatch — history disabled for this session'));
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

// ── Real boot sequence ──────────────────────────────────────────
// The spinner gates on genuine startup work: plugins actually load, then the
// relay connection is actually established. If the connection is slow it
// extends; if it times out we fall through to the TUI, which keeps retrying
// and shows the live connection status.
const pluginManager = new PluginManager();
const connection = new Connection(wsUrl);

await bootSequence([
  'Curve25519 key exchange',
  'XSalsa20-Poly1305 cipher',
  'Double Ratchet — forward secrecy',
  'TOFU trust store',
  { label: 'Loading plugins', task: () => pluginManager.loadAll() },
  {
    label: 'Connecting to relay',
    timeoutMs: 3500,
    task: () =>
      new Promise((resolve) => {
        if (connection.connected) {
          resolve();
          return;
        }
        connection.once('connected', resolve);
        connection.connect();
      }),
  },
]);

// ── Initialize ──────────────────────────────────────────────────

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

ui.setFingerprint(controller.fingerprint);
ui.addInfoMessage(`Your fingerprint: ${controller.fingerprint}`);
ui.addInfoMessage('Use /help to see available commands');

if (restoredState?.handshake) {
  ui.addSystemMessage('Previous session restored — ratchets preserved');
}

// The connection was already initiated during the boot sequence.

// Apply config toggles by replaying their slash-commands through the controller.
for (const cmd of startupCommands(config)) {
  ui.emit('input', cmd);
}

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
