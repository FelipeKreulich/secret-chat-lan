// Levenshtein edit distance between two short strings.
function editDistance(a, b) {
  const m = a.length;
  const n = b.length;
  if (m === 0) {
    return n;
  }
  if (n === 0) {
    return m;
  }

  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array(n + 1);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

/**
 * Suggest the closest known command to an unknown one.
 * Returns the nearest command within a small edit distance, or null.
 * @param {string} input - the command the user typed (e.g. "/exti")
 * @param {string[]} commands - canonical command list (e.g. ["/exit", ...])
 * @param {number} maxDistance - max edit distance to consider a match
 * @returns {string|null}
 */
export function suggestCommand(input, commands, maxDistance = 3) {
  if (typeof input !== 'string' || !Array.isArray(commands)) {
    return null;
  }
  const needle = input.toLowerCase();

  let best = null;
  let bestScore = Infinity;

  for (const cmd of commands) {
    const cand = cmd.toLowerCase();
    if (cand === needle) {
      return null; // exact match — nothing to suggest
    }
    // Strong signal: one is a prefix of the other (typo by truncation/extra char)
    const prefixBonus = cand.startsWith(needle) || needle.startsWith(cand) ? -1 : 0;
    const score = editDistance(needle, cand) + prefixBonus;
    if (score < bestScore) {
      bestScore = score;
      best = cmd;
    }
  }

  // Cap distance relative to command length so long words don't over-match
  return bestScore <= maxDistance ? best : null;
}
