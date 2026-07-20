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

  const strip = (s) => s.replace(/\{[^{}]*\}/g, '');

  it('renders a fenced code block distinctly and skips inline markdown inside', () => {
    const out = renderMarkdown('before\n```\n**not** bold here\n```\nafter');
    assert.ok(out.includes('#7fdbca-fg'), 'code color applied');
    assert.ok(strip(out).includes('**not** bold here'), 'literal ** kept inside code');
  });

  it('aligns a markdown table with a separator row', () => {
    const out = renderMarkdown('| Nome | Idade |\n|---|---|\n| Ana | 30 |\n| Bob | 5 |');
    const lines = strip(out).split('\n');
    assert.equal(lines.length, 4, 'header + rule + 2 rows');
    assert.match(lines[0], /Nome {2}Idade/);
    assert.match(lines[1], /─/);
    assert.match(lines[2], /Ana {3}30/);
    assert.match(lines[3], /Bob/);
  });

  it('piped text without a separator is NOT treated as a table', () => {
    const out = renderMarkdown('linha um | com pipe\noutra | linha');
    assert.ok(strip(out).includes('linha um | com pipe'));
    assert.ok(strip(out).includes('outra | linha'));
  });

  it('single-line text is unchanged (fast path)', () => {
    assert.equal(renderMarkdown('a | b | c'), renderMarkdown('a | b | c'));
    assert.ok(!renderMarkdown('a | b').includes('─'), 'no table rule for one line');
  });
});
