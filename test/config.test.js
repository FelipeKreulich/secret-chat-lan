import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig, startupCommands, loadConfig } from '../src/shared/config.js';

test('parseConfig keeps only whitelisted keys', () => {
  const cfg = parseConfig(
    JSON.stringify({
      nickname: 'felipe',
      server: 'wss://host:3600',
      sound: false,
      cover: 'constant',
      evil: 'rm -rf',
      __proto__: { polluted: true },
    }),
  );
  assert.deepEqual(cfg, {
    nickname: 'felipe',
    server: 'wss://host:3600',
    sound: false,
    cover: 'constant',
  });
  assert.equal({}.polluted, undefined, 'no prototype pollution');
});

test('parseConfig returns {} for invalid or non-object input', () => {
  assert.deepEqual(parseConfig('not json'), {});
  assert.deepEqual(parseConfig('[1,2,3]'), {});
  assert.deepEqual(parseConfig('42'), {});
  assert.deepEqual(parseConfig('null'), {});
});

test('loadConfig returns {} when the file is missing', () => {
  assert.deepEqual(loadConfig('/nonexistent/dir/ciphermesh-config.json'), {});
});

test('startupCommands maps toggles to their slash-commands', () => {
  assert.deepEqual(startupCommands({ sound: false, notify: false, receipts: false }), [
    '/sound off',
    '/notify off',
    '/receipts off',
  ]);
  assert.deepEqual(startupCommands({ deniable: true, cover: 'constant' }), [
    '/deniable on',
    '/cover constant',
  ]);
  assert.deepEqual(startupCommands({ cover: 'on' }), ['/cover on']);
  assert.deepEqual(startupCommands({}), []);
  // nickname/server are prompt defaults, not startup commands
  assert.deepEqual(startupCommands({ nickname: 'x', server: 'y' }), []);
});
