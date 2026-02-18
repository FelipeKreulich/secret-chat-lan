# Debugging Notes

## blessed + Windows: double keypress bug

**Problema**: No Windows, `blessed` dispara cada keypress 2 vezes — uma no `program.keypress` e outra no `screen.keypress`, com ~3ms de gap.

**Solução**:
1. NÃO usar `textbox` ou `textarea` (eles têm `readInput()` interno que duplica de novo)
2. Usar `blessed.box` simples + `screen.on('keypress')` manual
3. Dedup por `key.sequence + performance.now()` com janela de 25ms
4. Remover `fullUnicode: true` e `grabKeys` — mudam processamento de stdin

**Arquivo**: `src/client/UI.js` no projeto SecureLAN Chat
