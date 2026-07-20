import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDndWindow, inWindow, shouldNotify, mentionsMe } from '../src/shared/dnd.js';

test('parseDndWindow accepts HH:MM-HH:MM and rejects junk', () => {
  assert.deepEqual(parseDndWindow('22:00-08:00'), { start: 1320, end: 480 });
  assert.deepEqual(parseDndWindow('9:30-17:00'), { start: 570, end: 1020 });
  assert.equal(parseDndWindow('25:00-08:00'), null);
  assert.equal(parseDndWindow('22:70-08:00'), null);
  assert.equal(parseDndWindow('nope'), null);
});

test('inWindow handles same-day and midnight-wrapping windows', () => {
  const day = { start: 540, end: 1020 }; // 09:00-17:00
  assert.equal(inWindow(day, 600), true); // 10:00
  assert.equal(inWindow(day, 1100), false); // 18:20
  const night = { start: 1320, end: 480 }; // 22:00-08:00
  assert.equal(inWindow(night, 1380), true); // 23:00
  assert.equal(inWindow(night, 120), true); // 02:00
  assert.equal(inWindow(night, 720), false); // 12:00
  assert.equal(inWindow(null, 600), false);
});

test('shouldNotify follows the mode', () => {
  assert.equal(shouldNotify('off', null, 600, false), true);
  assert.equal(shouldNotify('on', null, 600, true), false, 'full silence ignores mentions');
  assert.equal(shouldNotify('mentions', null, 600, false), false);
  assert.equal(shouldNotify('mentions', null, 600, true), true);
});

test('a quiet-hours window forces mentions-only inside it', () => {
  const night = { start: 1320, end: 480 }; // 22:00-08:00
  // Inside the window: only mentions.
  assert.equal(shouldNotify('off', night, 1380, false), false, '23:00 non-mention silenced');
  assert.equal(shouldNotify('off', night, 1380, true), true, '23:00 mention breaks through');
  // Outside the window: the mode applies normally.
  assert.equal(shouldNotify('off', night, 720, false), true, '12:00 normal');
});

test('mentionsMe detects @nick and the bare word', () => {
  assert.equal(mentionsMe('hi @felipe how are you', 'felipe'), true);
  assert.equal(mentionsMe('felipe, did you see this?', 'felipe'), true);
  assert.equal(mentionsMe('the felipek spoke', 'felipe'), false, 'substring is not a mention');
  assert.equal(mentionsMe('nothing here', 'felipe'), false);
  assert.equal(mentionsMe('text', ''), false);
});
