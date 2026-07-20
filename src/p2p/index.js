import * as readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { readFileSync } from 'node:fs';
import sodium from 'sodium-native';
import boxen from 'boxen';
import {
  animatedBanner,
  bootSequence,
  promptLabel,
  promptDim,
  promptError,
  chalk,
  mint,
} from '../shared/banner.js';
import { KeyManager } from '../crypto/KeyManager.js';
import { StateManager } from '../crypto/StateManager.js';
import { questionHidden } from '../shared/prompt.js';
import { loadConfig, startupCommands } from '../shared/config.js';
import { setTheme } from '../shared/themes.js';
import { importBackup } from '../crypto/IdentityBackup.js';
import { Discovery } from './Discovery.js';
import { PeerServer } from './PeerServer.js';
import { PeerConnectionManager } from './PeerConnectionManager.js';
import { UI } from '../client/UI.js';
import { P2PChatController } from './P2PChatController.js';
import { PluginManager } from '../shared/PluginManager.js';

// ── Banner ──────────────────────────────────────────────────────
await animatedBanner('  ░▒▓  End-to-End Encrypted P2P Chat  ▓▒░');

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
      console.log(promptError('Wrong passphrase or corrupted state. New session.'));
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
        promptError('Passphrases do not match — the session will not be protected this time.'),
      );
    }
  }
}

// Offer to restore identity + trust from an encrypted backup.
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
        console.log(promptError('Invalid backup or wrong passphrase.'));
      }
    } catch (e) {
      console.log(promptError(`Could not read the backup: ${e.message}`));
    }
  }
}

rl.close();

// ── Initialize crypto ──────────────────────────────────────────
const keyManager = restoredState?.keyManager
  ? KeyManager.deserialize(restoredState.keyManager)
  : new KeyManager();

// ── Start P2P server ──────────────────────────────────────────
const peerServer = new PeerServer();
const port = await peerServer.start();

// ── Info box ────────────────────────────────────────────────────
console.log();
const lines = [];
lines.push(chalk.hex('#4cc9f0')('  Mode         ') + chalk.bold.white('P2P (mDNS LAN)'));
lines.push(chalk.hex('#4cc9f0')('  Port         ') + chalk.bold.white(port));
lines.push(chalk.hex('#4cc9f0')('  Fingerprint  ') + mint(keyManager.fingerprint));
lines.push(chalk.hex('#4cc9f0')('  Crypto       ') + chalk.white('X25519 + XSalsa20-Poly1305'));
lines.push(
  chalk.hex('#4cc9f0')('  Status       ') + chalk.bold.green('● Searching for peers on the LAN...'),
);

console.log(
  boxen(lines.join('\n'), {
    padding: { left: 1, right: 1, top: 0, bottom: 0 },
    borderColor: '#7b2dff',
    borderStyle: 'round',
    title: chalk.bold.hex('#00ff9f')(' P2P '),
    titleAlignment: 'center',
  }),
);
console.log();

// ── Real boot sequence ──────────────────────────────────────────
// The spinner gates on genuine startup work: the peer server is already
// listening (bound above) and plugins actually load. Peer discovery starts
// later, after the controller is wired, so no early mDNS events are missed.
const pluginManager = new PluginManager();

await bootSequence([
  'Curve25519 key exchange',
  'XSalsa20-Poly1305 cipher',
  'Double Ratchet — forward secrecy',
  'TOFU trust store',
  {
    label: `Peer server on :${port}`,
    task: async () => {
      if (!port) {
        throw new Error('peer server is not listening');
      }
    },
  },
  { label: 'Loading plugins', task: () => pluginManager.loadAll() },
]);

// ── Initialize components ──────────────────────────────────────
const connManager = new PeerConnectionManager(nickname, () => keyManager.publicKeyB64);
const discovery = new Discovery();
const ui = new UI(nickname);
const controller = new P2PChatController(
  nickname,
  peerServer,
  connManager,
  discovery,
  ui,
  keyManager,
  restoredState,
  pluginManager,
);

ui.setFingerprint(controller.fingerprint);
ui.addInfoMessage(`Your fingerprint: ${controller.fingerprint}`);
ui.addInfoMessage('P2P mode — peers discovered automatically via mDNS');
ui.addInfoMessage('Use /help to see available commands');

if (restoredState?.handshake) {
  ui.addSystemMessage('Previous session restored — ratchets preserved');
}

// Start mDNS discovery
discovery.start(nickname, port, keyManager.publicKeyB64);

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
