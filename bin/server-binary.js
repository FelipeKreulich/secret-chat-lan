// Entry point for the standalone relay binary (`bun build --compile`).
//
// Server-only on purpose: the TUI client depends on blessed, which resolves
// its widgets through dynamic requires that no bundler can follow. The relay
// has no such dependency, and "run a CipherMesh relay without installing
// Node" is exactly what self-hosters need.
import '../src/server/index.js';
