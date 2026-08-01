// Remembers where the user was (server + room) so the next launch can offer to
// reconnect. Deliberately tiny and best-effort: losing this file only costs a
// couple of keystrokes. Privacy: callers must NOT pass the room of a private
// room — its name never touches disk (see ChatController#saveLastSession).
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export function lastSessionPath() {
  return join(homedir(), '.ciphermesh', 'last-session.json');
}

/** Load { server, room?, at } or null when missing/corrupt. */
export function loadLastSession(path = lastSessionPath()) {
  try {
    const obj = JSON.parse(readFileSync(path, 'utf-8'));
    if (obj === null || typeof obj !== 'object' || typeof obj.server !== 'string') {
      return null;
    }
    const out = { server: obj.server, at: Number(obj.at) || 0 };
    if (typeof obj.room === 'string' && /^[a-zA-Z0-9_-]{1,30}$/.test(obj.room)) {
      out.room = obj.room;
    }
    return out;
  } catch {
    return null;
  }
}

/** Persist { server, room? }. Room is optional on purpose (private rooms). */
export function saveLastSession({ server, room }, path = lastSessionPath()) {
  if (typeof server !== 'string' || !server) {
    return;
  }
  const data = { server, at: Date.now() };
  if (typeof room === 'string' && room) {
    data.room = room;
  }
  try {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(data)}\n`, { mode: 0o600 });
  } catch {
    // Best effort — never break the chat over this.
  }
}

export function clearLastSession(path = lastSessionPath()) {
  try {
    if (existsSync(path)) {
      unlinkSync(path);
    }
  } catch {
    // Best effort.
  }
}
