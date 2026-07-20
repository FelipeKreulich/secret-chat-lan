// Subsequence fuzzy matching for the command palette. `query` matches `text`
// when its characters appear in order (not necessarily contiguous). Lower score
// = better match (earlier positions, fewer gaps). Returns -1 for no match.

export function fuzzyScore(text, query) {
  if (!query) {
    return 0;
  }
  const t = String(text).toLowerCase();
  const q = query.toLowerCase();
  let from = 0;
  let score = 0;
  let prev = -1;
  for (const ch of q) {
    const idx = t.indexOf(ch, from);
    if (idx === -1) {
      return -1;
    }
    score += idx; // earlier matches rank higher
    if (prev !== -1 && idx !== prev + 1) {
      score += 5; // penalise gaps (favour contiguous matches)
    }
    prev = idx;
    from = idx + 1;
  }
  return score;
}

// Filter + rank items by fuzzy match against a query. `key` extracts the string
// to match from each item. With no query, returns all items unchanged.
export function fuzzyFilter(items, query, key = (x) => x) {
  if (!query) {
    return items.slice();
  }
  return items
    .map((item) => ({ item, score: fuzzyScore(key(item), query) }))
    .filter((x) => x.score >= 0)
    .sort((a, b) => a.score - b.score || key(a.item).length - key(b.item).length)
    .map((x) => x.item);
}
