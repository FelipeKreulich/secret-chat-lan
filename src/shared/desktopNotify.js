// Desktop notifications, kept away from the chat UI.
//
// node-notifier drives SnoreToast on Windows. When notifications are disabled
// for the application, SnoreToast ignores the stdio pipes node-notifier gives
// it and writes its diagnostics to the *attached console* instead — the very
// console blessed is drawing the chat on. The result is unreadable: raw
// "Notifications are disabled / Reason: DisabledForApplication / Command Line:
// …snoretoast-x64.exe…" text smeared across the message log, once per message.
//
// Three guards, in order of importance:
//   1. On Windows every notification is delivered by a detached, console-less
//      helper process, so nothing the notifier prints can reach our terminal.
//   2. The first failure trips a breaker: desktop notifications go quiet for
//      the rest of the session and the caller is told once, in-app.
//   3. Notifications are throttled, so a burst of messages can't flood the
//      desktop (or, on the broken path, the terminal).

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Exit code the helper uses for "the OS refused to show the notification".
export const NOTIFY_FAILED_EXIT = 3;

// Minimum gap between two desktop notifications. Sound alerts and the unread
// pill are unthrottled — this only rate-limits the OS-level popup.
export const NOTIFY_MIN_INTERVAL_MS = 3000;

const WORKER_PATH = fileURLToPath(new URL('./notifyWorker.js', import.meta.url));

/**
 * True when the platform needs the out-of-process delivery path. Only Windows
 * has a notifier that writes to the console behind our back; macOS and Linux
 * back-ends stay in-process (spawning a Node runtime per message would be far
 * more expensive than the notification itself).
 */
export function needsIsolation(platform = process.platform) {
  return platform === 'win32';
}

/**
 * Desktop notifier with a breaker and a throttle.
 *
 * @param {object}   [opts]
 * @param {Function} [opts.onUnavailable] called once, with a human-readable
 *   reason, the first time the OS refuses a notification.
 * @param {number}   [opts.minIntervalMs] throttle window.
 * @param {Function} [opts.now] clock, for tests.
 */
export class DesktopNotifier {
  #available = true;
  #reported = false;
  #lastSentAt = 0;
  #onUnavailable;
  #minIntervalMs;
  #now;
  #isolate;
  #send;

  constructor({
    onUnavailable = null,
    minIntervalMs = NOTIFY_MIN_INTERVAL_MS,
    now = Date.now,
    isolate = needsIsolation(),
    send = null,
  } = {}) {
    this.#onUnavailable = onUnavailable;
    this.#minIntervalMs = minIntervalMs;
    this.#now = now;
    this.#isolate = isolate;
    this.#send = send; // injected transport, for tests
  }

  /** False once the OS has told us notifications are not going to work. */
  get available() {
    return this.#available;
  }

  /**
   * Fire a desktop notification. Never throws, never blocks, and never lets the
   * platform notifier write to our terminal.
   *
   * @returns {boolean} true if the notification was handed to the OS.
   */
  notify({ title, message, sound = false }) {
    if (!this.#available) {
      return false;
    }
    const at = this.#now();
    if (at - this.#lastSentAt < this.#minIntervalMs) {
      return false; // throttled — the sound alert already fired
    }
    this.#lastSentAt = at;

    const options = { title: String(title ?? ''), message: String(message ?? ''), sound: !!sound };
    try {
      if (this.#send) {
        this.#send(options, (err) => this.#onResult(err));
      } else if (this.#isolate) {
        this.#sendIsolated(options);
      } else {
        this.#sendInProcess(options);
      }
    } catch (err) {
      this.#onResult(err);
      return false;
    }
    return true;
  }

  /** Stop trying for the rest of the session (used by `/notify off`). */
  disable() {
    this.#available = false;
  }

  /**
   * Re-arm the breaker. `/notify on` means the user believes they fixed the OS
   * setting we tripped on, so give the platform another chance — including the
   * one-off in-app warning if it fails again.
   */
  reset() {
    this.#available = true;
    this.#reported = false;
    this.#lastSentAt = 0;
  }

  // Windows: a detached, hidden helper with no stdio and no console of its own.
  // Anything SnoreToast decides to print goes nowhere near the chat.
  #sendIsolated(options) {
    const child = spawn(process.execPath, [WORKER_PATH, JSON.stringify(options)], {
      detached: true,
      windowsHide: true,
      stdio: 'ignore',
    });
    child.on('error', (err) => this.#onResult(err));
    child.on('exit', (code) => {
      if (code === NOTIFY_FAILED_EXIT) {
        this.#onResult(new Error('the operating system refused the notification'));
      }
    });
    child.unref();
  }

  // macOS / Linux: in-process, but always with a callback so a failure is
  // handled instead of surfacing as an unhandled 'error' event.
  #sendInProcess(options) {
    import('node-notifier')
      .then(({ default: notifier }) => {
        notifier.notify(options, (err) => this.#onResult(err));
      })
      .catch((err) => this.#onResult(err));
  }

  #onResult(err) {
    if (!isFailure(err)) {
      return;
    }
    this.#available = false;
    if (this.#reported) {
      return;
    }
    this.#reported = true;
    this.#onUnavailable?.(describeFailure(err));
  }
}

/**
 * Whether what the notifier handed back is a real failure.
 *
 * node-notifier's `fileCommand` reports a non-zero exit as an Error but also
 * passes plain stderr through as the "error" argument on success — a chatty
 * `notify-send` or `terminal-notifier` build would otherwise mute notifications
 * for the whole session. Errors always count; loose text only when it names a
 * failure. Pure, exported for testing.
 */
export function isFailure(err) {
  if (!err) {
    return false;
  }
  if (err instanceof Error) {
    return true;
  }
  const text = String(err).trim();
  return (
    text !== '' && /\b(disabled|denied|not found|no such|fail|error|refus|invalid)/i.test(text)
  );
}

/**
 * Turn whatever the platform notifier reported into one short sentence. The raw
 * text is multi-line and full of absolute paths — exactly what we don't want in
 * the chat log. Pure, exported for testing.
 */
export function describeFailure(err) {
  const raw = String(err?.message ?? err ?? '')
    .replace(/\s+/g, ' ')
    .trim();
  if (/disabledforapplication|notifications are disabled/i.test(raw)) {
    return 'the OS has notifications turned off for this app';
  }
  if (/not found on system|enoent/i.test(raw)) {
    return 'no notification backend is installed';
  }
  return raw.slice(0, 120) || 'the OS rejected it';
}
