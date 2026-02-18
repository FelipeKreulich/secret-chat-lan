# Memory

## blessed + Windows
- Double keypress bug: cada tecla dispara 2x. Fix: box manual + dedup 25ms. Ver `debugging.md`

## SecureLAN Chat
- Projeto em `C:\Users\felip\Desktop\Felipe\Projetos\secret-chat-server`
- sodium-native v4 NÃO tem `crypto_box_beforenm`/`afternm` — usar `crypto_box_easy` direto
