import { appendFileSync, readFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export const AuditEvent = {
  TRUST_NEW_PEER: 'TRUST_NEW_PEER',
  TRUST_MISMATCH: 'TRUST_MISMATCH',
  TRUST_VERIFIED_MISMATCH: 'TRUST_VERIFIED_MISMATCH',
  KEY_ROTATION_OWN: 'KEY_ROTATION_OWN',
  KEY_ROTATION_PEER: 'KEY_ROTATION_PEER',
  SAS_VERIFY: 'SAS_VERIFY',
  SAS_CONFIRM: 'SAS_CONFIRM',
  DECRYPT_FAILURE: 'DECRYPT_FAILURE',
  NONCE_REPLAY: 'NONCE_REPLAY',
  PEER_CONNECTED: 'PEER_CONNECTED',
  PEER_DISCONNECTED: 'PEER_DISCONNECTED',
  ROOM_CHANGED: 'ROOM_CHANGED',
  ADMIN_KICK: 'ADMIN_KICK',
  ADMIN_MUTE: 'ADMIN_MUTE',
  ADMIN_BAN: 'ADMIN_BAN',
};

export class AuditLog {
  #filePath;

  constructor() {
    const dir = join(homedir(), '.ciphermesh');
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    this.#filePath = join(dir, 'audit.log');
  }

  log(eventType, details = {}) {
    const entry = {
      ts: new Date().toISOString(),
      event: eventType,
      ...details,
    };
    try {
      appendFileSync(this.#filePath, JSON.stringify(entry) + '\n', 'utf-8');
    } catch {
      // Silently fail — audit log should never break the app
    }
  }

  readLast(n = 20) {
    try {
      if (!existsSync(this.#filePath)) return [];
      const content = readFileSync(this.#filePath, 'utf-8').trim();
      if (!content) return [];
      const lines = content.split('\n');
      return lines.slice(-n).map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return { raw: line };
        }
      });
    } catch {
      return [];
    }
  }
}
