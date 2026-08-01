import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseThemeChoice, resolveServerAnswer, runOnboarding } from '../src/shared/onboarding.js';
import { saveConfig, hasConfigFile, loadConfig } from '../src/shared/config.js';
import { getThemeName, setTheme } from '../src/shared/themes.js';

const NAMES = ['neon', 'matrix', 'mono', 'sunset', 'ocean'];

// Readline stand-in: answers questions from a queue.
function fakeRl(answers) {
  const queue = [...answers];
  return {
    question: async () => (queue.length ? queue.shift() : ''),
  };
}

describe('onboarding — pure helpers', () => {
  it('parseThemeChoice accepts list numbers, names and falls back', () => {
    assert.equal(parseThemeChoice('2', NAMES, 'neon'), 'matrix');
    assert.equal(parseThemeChoice('ocean', NAMES, 'neon'), 'ocean');
    assert.equal(parseThemeChoice('  MONO ', NAMES, 'neon'), 'mono');
    assert.equal(parseThemeChoice('', NAMES, 'neon'), 'neon');
    assert.equal(parseThemeChoice('99', NAMES, 'neon'), 'neon');
    assert.equal(parseThemeChoice('vaporwave', NAMES, 'neon'), 'neon');
  });

  it('resolveServerAnswer keeps plain addresses and defaults on empty', () => {
    assert.deepEqual(resolveServerAnswer('192.168.1.7:3600'), {
      session: '192.168.1.7:3600',
      save: '192.168.1.7:3600',
    });
    assert.deepEqual(resolveServerAnswer('   '), {
      session: 'localhost:3600',
      save: 'localhost:3600',
    });
  });

  it('resolveServerAnswer uses an invite for the session but saves its host', () => {
    const invite = 'ciphermesh://100.64.0.9:3600/sala';
    const r = resolveServerAnswer(invite);
    assert.equal(r.session, invite, 'session keeps the invite (room included)');
    assert.equal(r.save, '100.64.0.9:3600', 'saved default is just the host');
  });
});

describe('onboarding — config persistence', () => {
  it('saveConfig writes whitelisted keys and hasConfigFile detects it', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'cm-onboard-')), 'config.json');
    assert.equal(hasConfigFile(path), false);

    saveConfig({ nickname: 'felipe', theme: 'ocean', evil: 'x' }, path);

    assert.equal(hasConfigFile(path), true);
    const loaded = loadConfig(path);
    assert.deepEqual(loaded, { nickname: 'felipe', theme: 'ocean' });
  });

  it('saveConfig merges over existing keys instead of wiping them', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'cm-onboard-')), 'config.json');
    saveConfig({ nickname: 'felipe', sound: false }, path);
    saveConfig({ theme: 'matrix' }, path);

    assert.deepEqual(loadConfig(path), { nickname: 'felipe', sound: false, theme: 'matrix' });
  });
});

describe('onboarding — wizard flow', () => {
  it('collects nickname, theme and server, and persists them', async () => {
    const prev = getThemeName();
    const path = join(mkdtempSync(join(tmpdir(), 'cm-onboard-')), 'config.json');
    const rl = fakeRl(['felipe', '2', '100.64.0.9:3600']);

    const result = await runOnboarding(rl, { savePath: path });

    assert.deepEqual(result, { nickname: 'felipe', server: '100.64.0.9:3600', theme: 'matrix' });
    assert.equal(existsSync(path), true, 'config file written');
    const saved = JSON.parse(readFileSync(path, 'utf-8'));
    assert.equal(saved.nickname, 'felipe');
    assert.equal(saved.theme, 'matrix');
    assert.equal(saved.server, '100.64.0.9:3600');
    assert.equal(getThemeName(), 'matrix', 'theme applied immediately');
    setTheme(prev);
  });

  it('re-asks until the nickname is valid and defaults theme/server on Enter', async () => {
    const prev = getThemeName();
    const path = join(mkdtempSync(join(tmpdir(), 'cm-onboard-')), 'config.json');
    const rl = fakeRl(['!!!', 'x'.repeat(30), 'ana', '', '']);

    const result = await runOnboarding(rl, { savePath: path });

    assert.equal(result.nickname, 'ana');
    assert.equal(result.server, 'localhost:3600');
    assert.equal(result.theme, prev, 'Enter keeps the current theme');
    setTheme(prev);
  });
});
