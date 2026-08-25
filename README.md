# `@tars/security`

The seed of the package `docs/cross-app/10` plans: encryption, identity, consent/access grants, RBAC.
Today it holds only the passphrase→key derivation shared by the QBO token vault (`EB1`) and the
health-dash vault (`HD1`), extracted in W72. See `kdf.ts`'s header for what is deliberately **not**
shared — the envelope formats stay distinct on purpose.

## Consumers import the source by RELATIVE path, not by `@tars/security/...`

This looks wrong and is deliberate. The bare-specifier form broke the Cloudflare Pages build on
2026-08-25, twice, and the reason generalises:

- `apps/health-dash-web/vite.config.ts` imports `src/lib/crypto.ts` (a dev-only endpoint needs
  `decryptVault`), so this package sits in the **config file's** module graph.
- Vite loads a config by bundling it with esbuild. Relative imports are **inlined**; bare specifiers
  that resolve into `node_modules` are **externalised** and handed to Node at run time.
- Cloudflare's build image runs **Node 22.16**, which does not strip TypeScript types. An externalised
  `.ts` file is therefore `ERR_UNKNOWN_FILE_EXTENSION` — while the same build passes on a newer local
  Node and in GitHub Actions, which is exactly why CI's `build` step went green over a broken deploy.

A relative import is inlined by every bundler and never handed to Node, so it works on every Node
version. That is the whole reason. Reproduce the failure before "tidying" this back:

```
NODE_OPTIONS=--no-experimental-strip-types npx vite build
```

The package keeps its `package.json` so npm treats it as a workspace member; it has no `exports` map
because nothing resolves it by specifier. If this repo ever grows a build step for `packages/*`, or
Node's type-stripping becomes universal, the bare form becomes safe again — and not before.
