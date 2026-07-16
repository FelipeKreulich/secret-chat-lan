import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isAudioFile, recordCommand, playCommand, guardPath } from '../src/shared/voiceNote.js';

test('isAudioFile matches common audio extensions only', () => {
  for (const n of ['nota.wav', 'a.OPUS', 'x.mp3', 'y.m4a', 'z.ogg', 'w.flac']) {
    assert.equal(isAudioFile(n), true, n);
  }
  for (const n of ['foto.png', 'doc.pdf', 'x.txt', '', undefined]) {
    assert.equal(isAudioFile(n), false, String(n));
  }
});

test('recordCommand builds a bounded-duration capture per tool', () => {
  assert.deepEqual(recordCommand('rec', '/tmp/a.wav', 5), {
    cmd: 'rec',
    args: ['-q', '/tmp/a.wav', 'trim', '0', '5'],
  });
  assert.deepEqual(recordCommand('sox', '/tmp/a.wav', 10), {
    cmd: 'sox',
    args: ['-q', '-d', '-t', 'wav', '/tmp/a.wav', 'trim', '0', '10'],
  });
  // ffmpeg uses the platform's capture backend
  assert.equal(recordCommand('ffmpeg', '/tmp/a.wav', 3, 'darwin').args.includes('avfoundation'), true);
  assert.equal(recordCommand('ffmpeg', '/tmp/a.wav', 3, 'linux').args.includes('alsa'), true);
  assert.equal(recordCommand('nope', '/tmp/a.wav', 3), null);
});

test('recordCommand clamps the duration to a whole positive number', () => {
  assert.equal(recordCommand('rec', '/tmp/a.wav', 0).args.at(-1), '1');
  assert.equal(recordCommand('rec', '/tmp/a.wav', 4.6).args.at(-1), '5');
});

test('playCommand builds a non-blocking playback per tool', () => {
  assert.deepEqual(playCommand('afplay', '/tmp/a.wav'), { cmd: 'afplay', args: ['/tmp/a.wav'] });
  assert.equal(playCommand('ffplay', '/tmp/a.wav').args.includes('-autoexit'), true);
  assert.equal(playCommand('nope', '/tmp/a.wav'), null);
});

test('a flag-looking path (peer-controlled filename) cannot smuggle argv flags', () => {
  // A malicious peer could name the note "-x.wav"; it must be treated as a file.
  assert.equal(guardPath('-x.wav'), './-x.wav');
  assert.equal(guardPath('--output=/etc/x'), './--output=/etc/x');
  assert.equal(guardPath('/abs/ok.wav'), '/abs/ok.wav'); // absolute paths untouched
  assert.equal(guardPath('rel/ok.wav'), 'rel/ok.wav');

  assert.equal(playCommand('afplay', '-x.wav').args[0], './-x.wav');
  assert.equal(recordCommand('rec', '-out.wav', 5).args[1], './-out.wav');
});
