# Contributing to CipherMesh

## Language

CipherMesh is published on npm and runs a public hub, so anything a stranger
might read is **English**:

| Where | Language |
|---|---|
| Code, comments, identifiers | **English** |
| User-facing strings (UI, `/help`, server logs, MOTD) | **English** |
| Issue titles and bodies | **English** |
| Pull request titles and bodies | **English** |
| Commit messages | Portuguese (Conventional Commits) |
| `README.md`, `TERMS.md` | English |
| `README.pt-BR.md` | Portuguese — keep in sync with the English one |

There is no i18n layer in the app: do not translate UI strings.

## Workflow

1. Open an **issue** describing the problem or the change.
2. Branch off `dev` — `feat/…`, `fix/…`, `chore/…`, `docs/…`.
3. Commit with a Conventional Commit message ending in `Refs #<issue>`.
4. PR into `dev`, then a release PR from `dev` into `master`.
5. Delete the feature branch.

`dev` and `master` are permanent and kept content-identical.

## Before you push

```bash
npm run validate      # lint + prettier + the whole test suite
```

Everything must be green. New behaviour needs a test; a bug fix needs a test
that fails without the fix.

## Releases

Bump the version on `dev`, update the tarball name in `Formula/ciphermesh.rb`,
merge into `master`, then push a `v*` tag. The tag runs the suite and then
publishes: npm (OIDC Trusted Publishing, no tokens), a GitHub Release, the
GHCR image, the standalone relay binaries, and finally deploys the public hub.

After the package is on npm, fill the real tarball digest into the Homebrew
formula:

```bash
curl -sL https://registry.npmjs.org/ciphermesh/-/ciphermesh-<version>.tgz | shasum -a 256
```

## Security

Never weaken a security property for convenience. If a change touches crypto,
the trust model, or the relay's zero-knowledge posture, say so explicitly in
the PR and explain why it is still safe. Report vulnerabilities privately —
see [SECURITY.md](SECURITY.md).
