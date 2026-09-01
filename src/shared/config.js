import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

// Optional user config at ~/.ciphermesh/config.json. Everything is a default the
// user can still override at the prompt or with a slash-command. Unknown keys
// are ignored (whitelist) so a typo can never inject behaviour.
const ALLOWED = [
  'nickname',
  'server',
  'sound',
  'notify',
  'cover',
  'receipts',
  'deniable',
  'theme',
  'autoAway',
  'autoLock',
  'dnd',
  // File names under ~/.ciphermesh/plugins the user has approved. A plugin is
  // arbitrary code in the chat process, so nothing there runs until it appears
  // here — see PluginManager.
  'pluginsAllowed',
  // false turns off the daily version check — the only request this client
  // ever makes to anything but the relay. See src/shared/updateCheck.js.
  'updateCheck',
];

export function configPath() {
  return join(homedir(), '.ciphermesh', 'config.json');
}

/** Parse + whitelist a raw config string. Pure — exported for testing. */
export function parseConfig(raw) {
  let obj;
  try {
    obj = JSON.parse(raw);
  } catch {
    return {};
  }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    return {};
  }
  const out = {};
  for (const k of ALLOWED) {
    if (obj[k] !== undefined) {
      out[k] = obj[k];
    }
  }
  // The only key whose *shape* matters: a hand-edited string here would be
  // iterated character by character, and "roll.js" would approve nothing while
  // looking like it approved something.
  if (out.pluginsAllowed !== undefined) {
    out.pluginsAllowed = Array.isArray(out.pluginsAllowed)
      ? out.pluginsAllowed.filter((entry) => typeof entry === 'string')
      : [];
  }
  return out;
}

/** Read the config file, returning {} if missing or unreadable. */
export function loadConfig(path = configPath()) {
  try {
    return parseConfig(readFileSync(path, 'utf-8'));
  } catch {
    return {};
  }
}

/** True if a config file already exists (used to detect the first run). */
export function hasConfigFile(path = configPath()) {
  return existsSync(path);
}

/**
 * Persist config (whitelisted keys only, merged over what's on disk so a
 * partial save never wipes hand-edited settings). Returns what was written.
 */
export function saveConfig(cfg, path = configPath()) {
  const merged = { ...loadConfig(path) };
  for (const k of ALLOWED) {
    if (cfg[k] !== undefined) {
      merged[k] = cfg[k];
    }
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(merged, null, 2)}\n`, { mode: 0o600 });
  return merged;
}

/**
 * Translate config toggles into the slash-commands that apply them, so startup
 * reuses the exact command handlers (no duplicated logic). Pure — testable.
 */
export function startupCommands(config) {
  const cmds = [];
  if (config.sound === false) {
    cmds.push('/sound off');
  } else if (config.sound === true) {
    cmds.push('/sound on');
  }
  if (config.notify === false) {
    cmds.push('/notify off');
  } else if (config.notify === true) {
    cmds.push('/notify on');
  }
  if (config.receipts === false) {
    cmds.push('/receipts off');
  }
  if (config.deniable === true) {
    cmds.push('/deniable on');
  }
  if (config.cover === 'on' || config.cover === 'jitter') {
    cmds.push('/cover on');
  } else if (config.cover === 'constant') {
    cmds.push('/cover constant');
  }
  if (Number.isInteger(config.autoAway) && config.autoAway > 0) {
    cmds.push(`/autoaway ${config.autoAway}`);
  }
  if (Number.isInteger(config.autoLock) && config.autoLock > 0) {
    cmds.push(`/autolock ${config.autoLock}`);
  }
  if (config.dnd === 'on' || config.dnd === 'mentions') {
    cmds.push(`/dnd ${config.dnd}`);
  } else if (typeof config.dnd === 'string' && /^\d/.test(config.dnd)) {
    cmds.push(`/dnd ${config.dnd}`);
  }
  return cmds;
}
