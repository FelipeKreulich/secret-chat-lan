import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { applyShortcodes, shortcodeSuggestions } from '../src/shared/emoji.js';

describe('Emoji shortcodes', () => {
  test('substitui shortcode conhecido', () => {
    assert.equal(applyShortcodes('bora :rocket:'), 'bora 🚀');
  });

  test('substitui varios na mesma mensagem', () => {
    assert.equal(applyShortcodes(':fire: e :100:'), '🔥 e 💯');
  });

  test('mantem shortcode desconhecido intacto', () => {
    assert.equal(applyShortcodes('sem :naoexiste: aqui'), 'sem :naoexiste: aqui');
  });

  test('nao mexe em texto sem shortcodes', () => {
    const text = 'mensagem normal, ate com : dois pontos soltos';
    assert.equal(applyShortcodes(text), text);
  });

  test('horario tipo 10:30 nao vira emoji', () => {
    assert.equal(applyShortcodes('reuniao as 10:30:00 ok'), 'reuniao as 10:30:00 ok');
  });

  test('sugestoes filtram por prefixo', () => {
    const s = shortcodeSuggestions(':s');
    assert.ok(s.includes(':smile:'));
    assert.ok(s.includes(':sad:'));
    assert.ok(!s.includes(':fire:'));
  });
});
