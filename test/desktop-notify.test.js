import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DesktopNotifier,
  describeFailure,
  isFailure,
  needsIsolation,
  NOTIFY_MIN_INTERVAL_MS,
} from '../src/shared/desktopNotify.js';

// A stub transport standing in for node-notifier / the detached helper.
function stub(err = null) {
  const calls = [];
  const send = (options, cb) => {
    calls.push(options);
    cb(err);
  };
  return { calls, send };
}

test('only Windows needs the out-of-process notifier', () => {
  assert.equal(needsIsolation('win32'), true);
  assert.equal(needsIsolation('darwin'), false);
  assert.equal(needsIsolation('linux'), false);
});

test('a successful notification reaches the platform', () => {
  const { calls, send } = stub();
  const n = new DesktopNotifier({ send, minIntervalMs: 0 });
  assert.equal(n.notify({ title: 'Ana', message: 'hi', sound: true }), true);
  assert.deepEqual(calls, [{ title: 'Ana', message: 'hi', sound: true }]);
  assert.equal(n.available, true);
});

test('the first refusal trips the breaker and reports once', () => {
  const { calls, send } = stub(new Error('Notifications are disabled'));
  const reasons = [];
  const n = new DesktopNotifier({
    send,
    minIntervalMs: 0,
    onUnavailable: (reason) => reasons.push(reason),
  });

  assert.equal(n.notify({ title: 'a', message: '1' }), true);
  assert.equal(n.available, false, 'breaker trips on the first failure');

  // A flood of further messages must not reach the platform at all — that is
  // the corruption the Windows bug produced, once per message.
  for (let i = 0; i < 20; i++) {
    assert.equal(n.notify({ title: 'a', message: String(i) }), false);
  }
  assert.equal(calls.length, 1, 'platform called exactly once');
  assert.deepEqual(reasons, ['the OS has notifications turned off for this app']);
});

test('notifications are throttled', () => {
  let clock = 1_000_000;
  const { calls, send } = stub();
  const n = new DesktopNotifier({ send, now: () => clock });

  assert.equal(n.notify({ title: 'a', message: '1' }), true);
  clock += NOTIFY_MIN_INTERVAL_MS - 1;
  assert.equal(n.notify({ title: 'a', message: '2' }), false, 'inside the window');
  clock += 1;
  assert.equal(n.notify({ title: 'a', message: '3' }), true, 'window elapsed');
  assert.deepEqual(
    calls.map((c) => c.message),
    ['1', '3'],
  );
});

test('a throwing transport is contained, not propagated', () => {
  const reasons = [];
  const n = new DesktopNotifier({
    minIntervalMs: 0,
    onUnavailable: (reason) => reasons.push(reason),
    send: () => {
      throw new Error('spawn ENOENT');
    },
  });
  assert.equal(n.notify({ title: 'a', message: 'b' }), false);
  assert.equal(n.available, false);
  assert.deepEqual(reasons, ['no notification backend is installed']);
});

test('reset re-arms the breaker so /notify on can retry', () => {
  let fail = true;
  const calls = [];
  const reasons = [];
  const n = new DesktopNotifier({
    minIntervalMs: 0,
    onUnavailable: (reason) => reasons.push(reason),
    send: (options, cb) => {
      calls.push(options);
      cb(fail ? new Error('Notifications are disabled') : null);
    },
  });

  n.notify({ title: 'a', message: '1' });
  assert.equal(n.available, false);

  fail = false;
  n.reset();
  assert.equal(n.available, true);
  assert.equal(n.notify({ title: 'a', message: '2' }), true);
  assert.equal(calls.length, 2);
  assert.equal(reasons.length, 1, 'the warning is still only shown once per failure');
});

test('disable() silences the notifier without a platform round trip', () => {
  const { calls, send } = stub();
  const n = new DesktopNotifier({ send, minIntervalMs: 0 });
  n.disable();
  assert.equal(n.notify({ title: 'a', message: 'b' }), false);
  assert.equal(calls.length, 0);
});

test('describeFailure keeps SnoreToast noise out of the chat log', () => {
  const snoretoast = new Error(
    'Notifications are disabled\nReason: DisabledForApplication Please make sure that the app id is set correctly.\n' +
      'Command Line: C:\\Users\\PROG\\AppData\\Local\\npm-cache\\_npx\\6ec\\node_modules\\node-notifier\\vendor\\snoreToast\\snoretoast-x64.exe -pipeName \\\\.\\pipe\\notifierPipe-d8a',
  );
  const described = describeFailure(snoretoast);
  assert.equal(described, 'the OS has notifications turned off for this app');
  assert.ok(!described.includes('\n'), 'never multi-line');
  assert.ok(!described.includes('snoretoast'), 'never leaks the command line');

  assert.equal(
    describeFailure(new Error('Notifier (x) not found on system.')),
    'no notification backend is installed',
  );
  assert.equal(describeFailure(null), 'the OS rejected it');
  assert.equal(describeFailure(new Error('x'.repeat(400))).length, 120, 'always bounded');
});

test('harmless stderr chatter does not mute notifications', () => {
  // node-notifier hands plain stderr back in the error slot even on success.
  assert.equal(isFailure(''), false);
  assert.equal(isFailure('   '), false);
  assert.equal(isFailure('Gtk-Message: Failed to load module "canberra"'), true, 'names a failure');
  assert.equal(isFailure('terminal-notifier 2.0.0'), false, 'version banner is not a failure');
  assert.equal(isFailure(new Error('Command failed')), true);
  assert.equal(isFailure(null), false);

  const calls = [];
  const reasons = [];
  const n = new DesktopNotifier({
    minIntervalMs: 0,
    onUnavailable: (reason) => reasons.push(reason),
    send: (options, cb) => {
      calls.push(options);
      cb('terminal-notifier 2.0.0');
    },
  });
  n.notify({ title: 'a', message: '1' });
  n.notify({ title: 'a', message: '2' });
  assert.equal(n.available, true, 'still armed after noisy-but-successful runs');
  assert.equal(calls.length, 2);
  assert.deepEqual(reasons, []);
});
