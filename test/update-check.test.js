import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  compareVersions,
  detectInstall,
  formatNotice,
  isDisabled,
  isNewer,
  runUpdate,
  shouldCheck,
} from '../src/shared/updateCheck.js';
import { offerUpdate } from '../src/shared/updateOffer.js';

const NPX = 'file:///Users/x/.npm/_npx/6ec7c9017afe923f/node_modules/ciphermesh/src/shared/x.js';
const BREW = 'file:///opt/homebrew/Cellar/ciphermesh/2.13.0/libexec/src/shared/x.js';
const GLOBAL = 'file:///usr/local/lib/node_modules/ciphermesh/src/shared/x.js';
const SOURCE = 'file:///Users/x/Projects/secret-chat-lan/src/shared/x.js';

describe('version comparison', () => {
  test('orders releases', () => {
    assert.equal(compareVersions('2.14.0', '2.14.1'), -1);
    assert.equal(compareVersions('2.14.1', '2.14.0'), 1);
    assert.equal(compareVersions('2.14.1', '2.14.1'), 0);
    assert.equal(compareVersions('2.9.0', '2.10.0'), -1, 'not string order');
    assert.equal(compareVersions('1.0.0', '2.0.0'), -1);
  });

  test('junk never claims an update', () => {
    // The registry is the one input here that is not ours. A garbled answer has
    // to read as "up to date", never as "newer".
    for (const bad of ['', null, undefined, 'latest', '../../etc', {}, '2.x']) {
      assert.equal(isNewer(bad, '2.14.1'), false, `${JSON.stringify(bad)} claimed newer`);
    }
    assert.equal(isNewer('2.14.2', '2.14.1'), true);
    assert.equal(isNewer('2.14.1', '2.14.1'), false, 'equal is not newer');
  });
});

describe('install detection', () => {
  test('names the right command for each way in', () => {
    assert.equal(detectInstall(NPX).kind, 'npx');
    assert.equal(detectInstall(BREW).kind, 'homebrew');
    assert.equal(detectInstall(GLOBAL).kind, 'global');
    assert.equal(detectInstall(SOURCE).kind, 'source');

    // The point of this: telling a Homebrew user to npm i -g leaves two copies
    // fighting over PATH, which is worse than the stale version they had.
    assert.deepEqual(detectInstall(BREW).update, ['brew', ['upgrade', 'ciphermesh']]);
    assert.deepEqual(detectInstall(GLOBAL).update, [
      'npm',
      ['install', '--global', 'ciphermesh@latest'],
    ]);
  });

  test('npx updates by running the new version, and carries the arguments', () => {
    const install = detectInstall(NPX, ['p2p', '--fresh']);
    assert.deepEqual(install.update, ['npx', ['--yes', 'ciphermesh@latest', 'p2p', '--fresh']]);
    assert.equal(install.relaunch, null, 'the update command IS the new version starting');
  });

  test('a checkout is only ever advised, never acted on', () => {
    const install = detectInstall(SOURCE);
    assert.equal(install.update, null);
    assert.match(formatNotice('2.13.0', '2.14.1', install), /git pull/);
  });

  test('windows paths are recognised too', () => {
    const win =
      'file:///C:/Users/PROG/AppData/Local/npm-cache/_npx/6ec/node_modules/ciphermesh/x.js';
    assert.equal(detectInstall(win).kind, 'npx');
  });
});

describe('when to go to the network at all', () => {
  test('at most once a day, never without a terminal, never when opted out', () => {
    const day = 24 * 60 * 60 * 1000;
    assert.equal(shouldCheck({ now: day, lastCheckedAt: 0 }), true);
    assert.equal(shouldCheck({ now: day - 1, lastCheckedAt: 0 }), false, 'inside the window');
    assert.equal(shouldCheck({ now: day, lastCheckedAt: 0, isTty: false }), false, 'piped');
    assert.equal(shouldCheck({ now: day, lastCheckedAt: 0, disabled: true }), false);
    assert.equal(shouldCheck({ now: day, lastCheckedAt: NaN }), true, 'a corrupt stamp checks');
  });

  test('both off switches work', () => {
    assert.equal(isDisabled({ CIPHERMESH_NO_UPDATE_CHECK: '1' }, {}), true);
    assert.equal(isDisabled({ NO_UPDATE_NOTIFIER: '1' }, {}), true);
    assert.equal(isDisabled({}, { updateCheck: false }), true);
    assert.equal(isDisabled({}, {}), false, 'on by default');
    assert.equal(isDisabled({}, { updateCheck: true }), false);
  });
});

describe('running the update', () => {
  const ok = () => ({ status: 0 });

  test('npx runs once — the update is the relaunch', () => {
    const calls = [];
    const code = runUpdate(detectInstall(NPX, ['client']), {
      spawn: (cmd, args) => {
        calls.push([cmd, ...args]);
        return ok();
      },
    });
    assert.deepEqual(calls, [['npx', '--yes', 'ciphermesh@latest', 'client']]);
    assert.equal(code, 0);
  });

  test('global installs update, then start the new binary by name', () => {
    // Never process.argv[1]: under npx that is the cache entry just replaced,
    // and relaunching it would bring the old version back up.
    const calls = [];
    runUpdate(detectInstall(GLOBAL, ['--fresh']), {
      spawn: (cmd, args) => {
        calls.push([cmd, ...args]);
        return ok();
      },
    });
    assert.deepEqual(calls, [
      ['npm', 'install', '--global', 'ciphermesh@latest'],
      ['ciphermesh', '--fresh'],
    ]);
  });

  test('a failed install does not relaunch, and lets the old version run', () => {
    const calls = [];
    const code = runUpdate(detectInstall(GLOBAL), {
      spawn: (cmd, args) => {
        calls.push(cmd);
        return { status: 1 };
      },
    });
    assert.deepEqual(calls, ['npm'], 'stopped after the failure');
    assert.equal(code, null, 'null means: carry on into the chat');
  });
});

describe('the startup offer', () => {
  const base = {
    now: 10 * 24 * 60 * 60 * 1000,
    state: { lastCheckedAt: 0, latest: null },
    save: () => {},
    run: () => 0,
    exit: () => {
      throw new Error('exited');
    },
    log: () => {},
    isTty: true,
    current: '2.14.1',
  };
  const never = { question: async () => assert.fail('should not have asked') };

  test('says nothing when up to date', async () => {
    await offerUpdate(never, SOURCE, [], {}, { ...base, fetch: async () => '0.0.1' });
  });

  test('says nothing when the registry is unreachable', async () => {
    // No network, a captive portal and a 500 all look the same, and all mean
    // "start the chat". A LAN tool is routinely run with no internet.
    await offerUpdate(never, SOURCE, [], {}, { ...base, fetch: async () => null });
  });

  test('does not even ask the network when it ran today', async () => {
    let asked = false;
    await offerUpdate(
      never,
      SOURCE,
      [],
      {},
      {
        ...base,
        state: { lastCheckedAt: base.now - 1000, latest: null },
        fetch: async () => {
          asked = true;
          return '99.0.0';
        },
      },
    );
    assert.equal(asked, false);
  });

  test('records the check even when it found nothing, so it backs off', async () => {
    const saved = [];
    await offerUpdate(
      never,
      SOURCE,
      [],
      {},
      { ...base, fetch: async () => null, save: (s) => saved.push(s) },
    );
    assert.equal(saved.length, 1);
    assert.equal(saved[0].lastCheckedAt, base.now);
  });

  test('offers, and skipping starts the chat on the old version', async () => {
    let ran = false;
    await offerUpdate(
      { question: async () => '' },
      GLOBAL,
      [],
      {},
      {
        ...base,
        fetch: async () => '99.0.0',
        run: () => {
          ran = true;
          return 0;
        },
      },
    );
    assert.equal(ran, false, 'Enter means skip');
  });

  test('accepting runs the update and leaves on its exit code', async () => {
    const exits = [];
    await offerUpdate(
      { question: async () => 'u' },
      GLOBAL,
      ['--fresh'],
      {},
      {
        ...base,
        fetch: async () => '99.0.0',
        run: () => 0,
        exit: (code) => exits.push(code),
      },
    );
    assert.deepEqual(exits, [0]);
  });

  test('a checkout is told what to run and never asked', async () => {
    const lines = [];
    await offerUpdate(
      never,
      SOURCE,
      [],
      {},
      { ...base, fetch: async () => '99.0.0', log: (l) => lines.push(l) },
    );
    assert.match(lines.join('\n'), /git pull/);
  });
});
