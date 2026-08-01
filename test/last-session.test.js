import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadLastSession, saveLastSession, clearLastSession } from '../src/shared/lastSession.js';

const temp = () => join(mkdtempSync(join(tmpdir(), 'cm-last-')), 'last-session.json');

describe('lastSession — remember where the user was', () => {
  it('round-trips server + room', () => {
    const path = temp();
    saveLastSession({ server: '100.73.206.23:3600', room: 'geral2' }, path);
    const loaded = loadLastSession(path);
    assert.equal(loaded.server, '100.73.206.23:3600');
    assert.equal(loaded.room, 'geral2');
    assert.ok(loaded.at > 0, 'timestamp recorded');
  });

  it('room is optional — private rooms save only the server', () => {
    const path = temp();
    saveLastSession({ server: 'host:3600' }, path);
    const loaded = loadLastSession(path);
    assert.equal(loaded.server, 'host:3600');
    assert.equal(loaded.room, undefined);
  });

  it('returns null for missing or corrupt files', () => {
    const path = temp();
    assert.equal(loadLastSession(path), null);
    writeFileSync(path, 'not json');
    assert.equal(loadLastSession(path), null);
    writeFileSync(path, JSON.stringify({ room: 'x' })); // no server
    assert.equal(loadLastSession(path), null);
  });

  it('rejects an invalid room name instead of propagating it', () => {
    const path = temp();
    writeFileSync(path, JSON.stringify({ server: 'h:1', room: 'bad room!!' }));
    const loaded = loadLastSession(path);
    assert.equal(loaded.server, 'h:1');
    assert.equal(loaded.room, undefined, 'invalid room dropped');
  });

  it('save without a server is a no-op; clear removes the file', () => {
    const path = temp();
    saveLastSession({ room: 'x' }, path);
    assert.equal(existsSync(path), false, 'nothing written without a server');

    saveLastSession({ server: 'h:1' }, path);
    assert.equal(existsSync(path), true);
    clearLastSession(path);
    assert.equal(existsSync(path), false);
    clearLastSession(path); // idempotent
  });
});
