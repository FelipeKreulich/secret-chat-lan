import { spawn, execFileSync } from 'node:child_process';
import { platform } from 'node:os';
import { join } from 'node:path';

// Voice notes reuse the encrypted file-transfer path: record to a temp .wav,
// send it as a file, and the receiver can play it back. Recording/playback is
// delegated to whatever CLI audio tool is installed (sox / ffmpeg / afplay),
// so this module stays a thin, mostly-pure wrapper.

const AUDIO_RE = /\.(wav|opus|mp3|m4a|ogg|flac|aac)$/i;

/** True if a filename looks like an audio note. */
export function isAudioFile(name) {
  return AUDIO_RE.test(name || '');
}

/** Build the record command for a detected tool. Pure — exported for testing. */
export function recordCommand(tool, outPath, seconds, os = platform()) {
  const dur = String(Math.max(1, Math.round(seconds)));
  switch (tool) {
    case 'rec': // sox's record frontend
      return { cmd: 'rec', args: ['-q', outPath, 'trim', '0', dur] };
    case 'sox':
      return { cmd: 'sox', args: ['-q', '-d', '-t', 'wav', outPath, 'trim', '0', dur] };
    case 'ffmpeg':
      return {
        cmd: 'ffmpeg',
        args: [
          '-y',
          '-f',
          os === 'darwin' ? 'avfoundation' : 'alsa',
          '-i',
          os === 'darwin' ? ':0' : 'default',
          '-t',
          dur,
          outPath,
        ],
      };
    default:
      return null;
  }
}

/** Build the playback command for a detected tool. Pure — exported for testing. */
export function playCommand(tool, path) {
  switch (tool) {
    case 'afplay': // macOS, built-in
      return { cmd: 'afplay', args: [path] };
    case 'play': // sox
      return { cmd: 'play', args: ['-q', path] };
    case 'ffplay':
      return { cmd: 'ffplay', args: ['-nodisp', '-autoexit', '-loglevel', 'quiet', path] };
    default:
      return null;
  }
}

function commandExists(cmd) {
  try {
    execFileSync(platform() === 'win32' ? 'where' : 'which', [cmd], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/** First available recording tool, or null. */
export function detectRecorder() {
  for (const tool of ['rec', 'sox', 'ffmpeg']) {
    if (commandExists(tool)) {
      return tool;
    }
  }
  return null;
}

/** First available playback tool, or null (afplay ships with macOS). */
export function detectPlayer() {
  const candidates = platform() === 'darwin' ? ['afplay', 'play', 'ffplay'] : ['play', 'ffplay'];
  for (const tool of candidates) {
    if (commandExists(tool)) {
      return tool;
    }
  }
  return null;
}

/**
 * Record `seconds` of audio into `dir`, resolving with the file path.
 * The tool auto-stops after the duration (sox `trim` / ffmpeg `-t`).
 */
export function recordVoiceNote(dir, seconds, now) {
  const tool = detectRecorder();
  if (!tool) {
    return Promise.reject(
      new Error('nenhum gravador encontrado — instale sox (ex: brew install sox)'),
    );
  }
  const out = join(dir, `voice-${now}.wav`);
  const spec = recordCommand(tool, out, seconds);
  return new Promise((resolve, reject) => {
    const proc = spawn(spec.cmd, spec.args, { stdio: 'ignore' });
    proc.on('error', reject);
    proc.on('exit', (code) => (code === 0 ? resolve(out) : reject(new Error('falha ao gravar'))));
  });
}

/** Play an audio file, resolving when playback finishes. */
export function playVoiceNote(path) {
  const tool = detectPlayer();
  if (!tool) {
    return Promise.reject(
      new Error('nenhum player de audio encontrado (instale sox ou use macOS)'),
    );
  }
  const spec = playCommand(tool, path);
  return new Promise((resolve, reject) => {
    const proc = spawn(spec.cmd, spec.args, { stdio: 'ignore' });
    proc.on('error', reject);
    proc.on('exit', () => resolve());
  });
}
