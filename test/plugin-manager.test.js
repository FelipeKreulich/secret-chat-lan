import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PluginManager } from '../src/shared/PluginManager.js';
import roll from '../examples/plugins/roll.js';
import poll from '../examples/plugins/poll.js';

describe('PluginManager', () => {
  it('loads valid plugins, skips broken/anonymous ones, normalizes commands', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cm-plugins-'));
    writeFileSync(
      join(dir, 'good.js'),
      "export default { name: 'good', commands: { hi: (args) => ({ info: `oi ${args.join(' ')}` }), '/Loud': () => 'LOUD' } };",
    );
    writeFileSync(join(dir, 'broken.js'), 'this is not javascript {{{');
    writeFileSync(join(dir, 'anon.js'), 'export default { commands: {} };');

    const pm = new PluginManager();
    await pm.loadAll(dir);

    assert.equal(pm.pluginCount, 1);
    assert.deepEqual(pm.getPluginNames(), ['good']);
    assert.deepEqual(pm.getCommandNames().sort(), ['/hi', '/loud']);
    assert.deepEqual(pm.handleCommand('/hi', ['tudo', 'bem']), { info: 'oi tudo bem' });
    assert.equal(pm.handleCommand('/LOUD', []), 'LOUD', 'lookup is case-insensitive');
    assert.equal(pm.handleCommand('/nope', []), null);
  });

  it('creates the plugin dir when missing and swallows handler throws', async () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'cm-plugins-')), 'nested');
    const pm = new PluginManager();
    await pm.loadAll(dir);
    assert.equal(existsSync(dir), true, 'directory created');

    const dir2 = mkdtempSync(join(tmpdir(), 'cm-plugins-'));
    writeFileSync(
      join(dir2, 'boom.js'),
      "export default { name: 'boom', commands: { boom: () => { throw new Error('x'); } } };",
    );
    const pm2 = new PluginManager();
    await pm2.loadAll(dir2);
    assert.equal(pm2.handleCommand('/boom', []), null, 'a throwing handler is treated as null');
  });
});

describe('example plugins', () => {
  it('roll: valid specs send to the room; invalid ones stay local', () => {
    const sent = roll.commands.roll(['2d6+1']);
    assert.ok(sent.send, 'valid roll is a send');
    assert.match(sent.send, /🎲 rolled 2d6\+1: \*\*\d+\*\* \(\d \+ \d \+1\)/);

    const total = Number(sent.send.match(/\*\*(\d+)\*\*/)[1]);
    assert.ok(total >= 3 && total <= 13, `total ${total} within 2d6+1 bounds`);

    assert.ok(roll.commands.roll(['banana']).info, 'invalid spec is a local usage note');
    assert.ok(roll.commands.roll([]).send, 'default d6 works');
  });

  it('poll: builds a numbered reaction poll; bad input stays local', () => {
    const sent = poll.commands.poll('Pizza hoje? | sim | claro | óbvio'.split(' '));
    assert.ok(sent.send);
    const lines = sent.send.split('\n');
    assert.equal(lines[0], '📊 **Pizza hoje?**');
    assert.equal(lines[1], '1️⃣ sim');
    assert.equal(lines[3], '3️⃣ óbvio');
    assert.match(lines[4], /\/react 1️⃣/);

    assert.ok(poll.commands.poll(['sem', 'opções']).info, 'no pipes → usage note');
    assert.ok(poll.commands.poll('só uma? | opção'.split(' ')).info, '<2 options → usage note');
  });
});
