import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  detectImageProtocol,
  supportsTrueColor,
  encodeITermImage,
  encodeKittyImage,
} from '../src/shared/terminalGraphics.js';

describe('terminalGraphics — detection', () => {
  it('detects kitty', () => {
    assert.equal(detectImageProtocol({ TERM: 'xterm-kitty' }), 'kitty');
    assert.equal(detectImageProtocol({ KITTY_WINDOW_ID: '1' }), 'kitty');
  });

  it('detects iTerm2', () => {
    assert.equal(detectImageProtocol({ TERM_PROGRAM: 'iTerm.app' }), 'iterm');
    assert.equal(detectImageProtocol({ LC_TERMINAL: 'iTerm2' }), 'iterm');
  });

  it('returns null for plain terminals', () => {
    assert.equal(detectImageProtocol({ TERM: 'xterm-256color' }), null);
    assert.equal(detectImageProtocol({}), null);
  });

  it('detects truecolor support', () => {
    assert.equal(supportsTrueColor({ COLORTERM: 'truecolor' }), true);
    assert.equal(supportsTrueColor({ COLORTERM: '24bit' }), true);
    assert.equal(supportsTrueColor({ TERM_PROGRAM: 'iTerm.app' }), true);
    assert.equal(supportsTrueColor({ TERM: 'xterm' }), false);
  });
});

describe('terminalGraphics — encoders', () => {
  it('iTerm2 escape wraps base64 with the 1337 File sequence', () => {
    const buf = Buffer.from('fake image bytes');
    const esc = encodeITermImage(buf, { widthCells: 40 });
    assert.ok(esc.startsWith('\x1b]1337;File='));
    assert.ok(esc.endsWith('\x07'));
    assert.ok(esc.includes(`size=${buf.length}`));
    assert.ok(esc.includes('width=40'));
    assert.ok(esc.includes(buf.toString('base64')));
  });

  it('kitty escape chunks a large payload with continuation markers', () => {
    const big = Buffer.alloc(10_000, 7); // > 4096 base64 chars → multiple chunks
    const esc = encodeKittyImage(big);
    assert.ok(esc.startsWith('\x1b_Gf=100,a=T,m=1;'), 'first chunk announces PNG + more');
    assert.ok(esc.includes('\x1b_Gm=1;'), 'has continuation chunks');
    assert.ok(esc.includes('\x1b_Gm=0;'), 'last chunk marks end');
    assert.ok(esc.endsWith('\x1b\\'));
  });

  it('kitty escape for a small payload is a single m=0 chunk', () => {
    const esc = encodeKittyImage(Buffer.from('tiny'));
    assert.ok(esc.startsWith('\x1b_Gf=100,a=T,m=0;'));
    assert.equal((esc.match(/\x1b_G/g) || []).length, 1);
  });
});
