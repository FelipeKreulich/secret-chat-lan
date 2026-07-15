import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { keyArt } from '../src/shared/keyArt.js';

describe('keyArt (drunken bishop)', () => {
  it('is deterministic for the same input', () => {
    const bytes = Buffer.from('0011223344556677889900aabbccddeeff', 'hex');
    assert.equal(keyArt(bytes), keyArt(bytes));
  });

  it('differs for different inputs', () => {
    const a = keyArt(Buffer.from('00'.repeat(16), 'hex'));
    const b = keyArt(Buffer.from('ff'.repeat(16), 'hex'));
    assert.notEqual(a, b);
  });

  it('has the expected box dimensions (11 lines of 19 columns)', () => {
    const lines = keyArt(Buffer.from('deadbeef', 'hex')).split('\n');
    assert.equal(lines.length, 11);
    for (const l of lines) {
      assert.equal(l.length, 19);
    }
  });

  it('draws S (start) and E (end) markers', () => {
    const art = keyArt(Buffer.from('abcdef1234567890', 'hex'));
    assert.ok(art.includes('S'));
    assert.ok(art.includes('E'));
  });

  it('centers a title on the top border', () => {
    const first = keyArt(Buffer.from('00', 'hex'), 'alice').split('\n')[0];
    assert.ok(first.startsWith('+'));
    assert.ok(first.endsWith('+'));
    assert.ok(first.includes('[alice]'));
    assert.equal(first.length, 19);
  });
});
