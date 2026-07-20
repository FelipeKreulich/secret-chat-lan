import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

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
  'dnd',
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
  if (config.dnd === 'on' || config.dnd === 'mentions') {
    cmds.push(`/dnd ${config.dnd}`);
  } else if (typeof config.dnd === 'string' && /^\d/.test(config.dnd)) {
    cmds.push(`/dnd ${config.dnd}`);
  }
  return cmds;
}
