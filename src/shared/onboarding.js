// First-run setup wizard: ~30 seconds from `npx ciphermesh` to chatting, with
// just enough context to use the security features. Runs when no config file
// exists yet (or on demand via --setup) and persists the answers so it never
// asks twice.
import chalk from 'chalk';
import { SERVER_PORT } from './constants.js';
import { promptLabel, promptDim, promptError } from './banner.js';
import { themeNames, setTheme, getThemeName, THEMES } from './themes.js';
import { parseInvite } from './invite.js';
import { configPath, saveConfig } from './config.js';

/**
 * Resolve a theme answer: a number from the printed list ("2"), a name
 * ("matrix"), or empty → fallback. Pure — exported for testing.
 */
export function parseThemeChoice(input, names, fallback) {
  const clean = (input || '').trim().toLowerCase();
  if (!clean) {
    return fallback;
  }
  if (/^\d+$/.test(clean)) {
    const idx = Number(clean) - 1;
    return names[idx] || fallback;
  }
  return names.includes(clean) ? clean : fallback;
}

/**
 * Resolve the server answer into what to use this session and what to save
 * as the default. Invites are used as-is for the session but saved as their
 * host:port (a room invite is one-shot, the host is worth keeping).
 * Pure — exported for testing.
 */
export function resolveServerAnswer(input, fallback = `localhost:${SERVER_PORT}`) {
  const clean = (input || '').trim();
  if (!clean) {
    return { session: fallback, save: fallback };
  }
  const invite = parseInvite(clean);
  if (invite) {
    return { session: clean, save: invite.wsUrl.replace(/^wss?:\/\//, '') };
  }
  return { session: clean, save: clean };
}

/**
 * Interactive first-run wizard. Uses the same readline interface as the rest
 * of startup. Returns `{ nickname, server, theme }` — the caller uses them
 * directly for this session (no duplicate prompts) — after persisting them
 * to the config file.
 */
export async function runOnboarding(rl, { savePath = configPath() } = {}) {
  const dim = (t) => console.log(promptDim(`  ${t}`));

  console.log();
  console.log(chalk.bold.white('  First time here? Quick setup — 30 seconds.'));
  dim(`Everything is saved to ${savePath} (re-run anytime with: ciphermesh --setup)`);
  console.log();
  console.log(chalk.white('  How CipherMesh works, in three lines:'));
  dim('• Everything is end-to-end encrypted — the relay only ever sees ciphertext.');
  dim('• Your identity is a keypair; its short fingerprint is shown when you connect.');
  dim('• Verify friends out-of-band with /verify — a green ✓ appears next to their name.');
  console.log();

  // 1. Nickname
  let nickname = '';
  while (!nickname) {
    const raw = await rl.question(promptLabel(`Nickname ${promptDim('(a-z, 0-9, _, -)')}: `));
    const clean = raw.trim().replace(/[^a-zA-Z0-9_-]/g, '');
    if (clean.length >= 1 && clean.length <= 20) {
      nickname = clean;
    } else {
      console.log(promptError('Invalid nickname. Use 1-20 alphanumeric characters.'));
    }
  }

  // 2. Theme
  const names = themeNames();
  console.log();
  console.log(chalk.white('  Colour theme for nicknames:'));
  names.forEach((name, i) => {
    const swatch = THEMES[name]
      .slice(0, 5)
      .map((c) => (c.startsWith('#') ? chalk.hex(c)('█') : chalk[c]?.('█') || '█'))
      .join('');
    console.log(promptDim(`    ${i + 1}. ${name.padEnd(8)} ${swatch}`));
  });
  const themeRaw = await rl.question(
    promptLabel(`Theme ${promptDim(`(1-${names.length} or name, Enter = ${getThemeName()})`)}: `),
  );
  const theme = parseThemeChoice(themeRaw, names, getThemeName());
  setTheme(theme);

  // 3. Default server
  console.log();
  console.log(chalk.white('  Which server should be your default?'));
  dim(`• Same machine as the relay → localhost:${SERVER_PORT}`);
  dim(`• Someone else hosts it (LAN/Tailscale) → their IP, e.g. 100.64.0.9:${SERVER_PORT}`);
  dim('• Got a ciphermesh:// invite? Paste it here.');
  const serverRaw = await rl.question(
    promptLabel(`Server ${promptDim(`(Enter = localhost:${SERVER_PORT})`)}: `),
  );
  const { session: server, save: serverToSave } = resolveServerAnswer(serverRaw);

  saveConfig({ nickname, theme, server: serverToSave }, savePath);
  console.log();
  console.log(promptLabel('Setup saved — next time you go straight to the chat.'));
  console.log();

  return { nickname, server, theme };
}
