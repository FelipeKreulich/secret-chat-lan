// Do-not-disturb / mentions-only notification gating.
// mode: 'off' (normal), 'mentions' (only @mentions), 'on' (full silence).
// An optional quiet-hours window makes the effective mode 'mentions' inside it.

export function parseDndWindow(str) {
  const m = String(str).match(/^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$/);
  if (!m) {
    return null;
  }
  const h1 = Number(m[1]);
  const min1 = Number(m[2]);
  const h2 = Number(m[3]);
  const min2 = Number(m[4]);
  if (h1 > 23 || h2 > 23 || min1 > 59 || min2 > 59) {
    return null;
  }
  return { start: h1 * 60 + min1, end: h2 * 60 + min2 };
}

export function inWindow(window, nowMinutes) {
  if (!window) {
    return false;
  }
  const { start, end } = window;
  // Handle windows that wrap past midnight (e.g. 22:00-08:00).
  return start <= end
    ? nowMinutes >= start && nowMinutes < end
    : nowMinutes >= start || nowMinutes < end;
}

// Whether an incoming message should notify at all. A 'true' result still lets
// the caller apply its own sound/desktop-enabled toggles.
export function shouldNotify(mode, window, nowMinutes, mentioned) {
  const eff = inWindow(window, nowMinutes) ? 'mentions' : mode;
  if (eff === 'on') {
    return false; // full silence
  }
  if (eff === 'mentions') {
    return !!mentioned;
  }
  return true; // 'off' → normal
}

export function nowMinutes(date = new Date()) {
  return date.getHours() * 60 + date.getMinutes();
}

// True if `text` mentions `nickname` (via @nick or the bare word). Nicknames are
// validated to [a-zA-Z0-9_-], so no regex escaping is needed.
export function mentionsMe(text, nickname) {
  if (typeof text !== 'string' || !nickname) {
    return false;
  }
  const nick = nickname.toLowerCase();
  const t = text.toLowerCase();
  if (t.includes(`@${nick}`)) {
    return true;
  }
  return new RegExp(`(^|[^a-z0-9_-])${nick}([^a-z0-9_-]|$)`).test(t);
}
