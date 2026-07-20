import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fuzzyScore, fuzzyFilter } from '../src/shared/fuzzy.js';

test('fuzzyScore matches subsequences and rejects non-matches', () => {
  assert.ok(fuzzyScore('/deniable', 'den') >= 0);
  assert.ok(fuzzyScore('/deniable', 'dnb') >= 0, 'non-contiguous subsequence matches');
  assert.equal(fuzzyScore('/deniable', 'xyz'), -1);
  assert.equal(fuzzyScore('/deniable', 'denz'), -1, 'partial then miss → no match');
  assert.equal(fuzzyScore('anything', ''), 0, 'empty query matches with score 0');
});

test('fuzzyScore prefers earlier and more contiguous matches', () => {
  // "cov" is contiguous at the start of "/cover" → better (lower) than in "/discover"
  assert.ok(fuzzyScore('/cover', 'cov') < fuzzyScore('/discover-something', 'cov'));
  // contiguous beats gapped
  assert.ok(fuzzyScore('abcde', 'abc') < fuzzyScore('axbxcxd', 'abc'));
});

test('fuzzyFilter ranks and drops non-matches; empty query returns all', () => {
  const cmds = ['/deniable', '/delete', '/cover', '/theme', '/panic'];
  const out = fuzzyFilter(cmds, 'de');
  assert.ok(out.includes('/deniable') && out.includes('/delete'));
  assert.ok(!out.includes('/cover'));
  assert.deepEqual(fuzzyFilter(cmds, ''), cmds);
});

test('fuzzyFilter works with a key extractor', () => {
  const items = [
    { cmd: '/cover', desc: 'cover traffic' },
    { cmd: '/theme', desc: 'colors' },
  ];
  const out = fuzzyFilter(items, 'cov', (x) => x.cmd);
  assert.equal(out.length, 1);
  assert.equal(out[0].cmd, '/cover');
});
