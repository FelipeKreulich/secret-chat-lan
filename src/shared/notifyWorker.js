#!/usr/bin/env node
// One-shot desktop-notification helper.
//
// Spawned detached, hidden and with stdio ignored (see desktopNotify.js), so it
// owns no console: when SnoreToast writes its "Notifications are disabled"
// diagnostics past the stdio pipes, they land in this process's void instead of
// on top of the chat UI.
//
// Reads a single JSON argument ({ title, message, sound }) and exits 0 on
// success, NOTIFY_FAILED_EXIT when the OS refused the notification.

import notifier from 'node-notifier';
import { NOTIFY_FAILED_EXIT } from './desktopNotify.js';

// The platform callback only fires when the toast is dismissed or times out on
// screen, which can be tens of seconds — so this cap is a leak guard, not a
// verdict. Exiting 0 here means "handed over, outcome unknown"; only an actual
// error from the notifier is allowed to trip the caller's breaker.
const TIMEOUT_MS = 8000;

function main() {
  let options;
  try {
    options = JSON.parse(process.argv[2] || '{}');
  } catch {
    process.exit(NOTIFY_FAILED_EXIT);
  }

  const timer = setTimeout(() => process.exit(0), TIMEOUT_MS);
  timer.unref();

  try {
    notifier.notify(
      {
        title: String(options.title ?? ''),
        message: String(options.message ?? ''),
        sound: !!options.sound,
      },
      (err) => process.exit(err ? NOTIFY_FAILED_EXIT : 0),
    );
  } catch {
    process.exit(NOTIFY_FAILED_EXIT);
  }
}

main();
