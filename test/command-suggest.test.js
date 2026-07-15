import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { suggestCommand } from '../src/shared/commandSuggest.js';

const COMMANDS = ['/help', '/quit', '/users', '/join', '/rooms', '/msg', '/verify', '/kick'];

describe('suggestCommand', () => {
  it('suggests the nearest command for a typo', () => {
    assert.equal(suggestCommand('/qut', COMMANDS), '/quit');
    assert.equal(suggestCommand('/halp', COMMANDS), '/help');
    assert.equal(suggestCommand('/kik', COMMANDS), '/kick');
  });

  it('maps common aliases to the closest real command', () => {
    assert.equal(suggestCommand('/exit', COMMANDS), '/quit');
    assert.equal(suggestCommand('/user', COMMANDS), '/users'); // prefix
    assert.equal(suggestCommand('/room', COMMANDS), '/rooms'); // prefix
  });

  it('returns null for an exact match (nothing to suggest)', () => {
    assert.equal(suggestCommand('/help', COMMANDS), null);
    assert.equal(suggestCommand('/HELP', COMMANDS), null); // case-insensitive
  });

  it('returns null when nothing is close enough', () => {
    assert.equal(suggestCommand('/xyzzy', COMMANDS), null);
    assert.equal(suggestCommand('/completelydifferent', COMMANDS), null);
  });

  it('handles bad input gracefully', () => {
    assert.equal(suggestCommand(null, COMMANDS), null);
    assert.equal(suggestCommand('/help', null), null);
  });
});
