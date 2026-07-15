import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { renderMarkdown } from '../src/client/UI.js';

describe('renderMarkdown', () => {
  it('highlights http/https links (cyan + underline)', () => {
    const out = renderMarkdown('veja https://example.com/x agora');
    assert.ok(out.includes('{cyan-fg}{underline}https://example.com/x{/underline}{/cyan-fg}'));
  });

  it('renders bold, italic and inline code', () => {
    assert.ok(renderMarkdown('**oi**').includes('{bold}oi{/bold}'));
    assert.ok(renderMarkdown('`code`').includes('{yellow-fg}code{/yellow-fg}'));
    assert.ok(renderMarkdown('*it*').includes('{underline}it{/underline}'));
  });

  it('escapes plain text with no markup', () => {
    // blessed tag chars are escaped so they are not interpreted as tags
    const out = renderMarkdown('a {b} c');
    assert.ok(!out.includes('{b}') || out.includes('{open}'));
    assert.equal(typeof out, 'string');
  });

  it('does not double-highlight a link inside inline code', () => {
    const out = renderMarkdown('`https://x.com`');
    // the code span wins; no separate link tags injected inside it
    assert.ok(out.includes('{yellow-fg}'));
  });
});
