# `@tars/security`

Runtime-agnostic building blocks for encrypting per-user data and controlling who can decrypt
it: a shared key-derivation function, an authenticated envelope format with multi-principal
access via wrapped data-encryption keys, and storage-agnostic contracts for the account/vault/
grant data model those envelopes sit on top of.

Built for and extracted from a health-records app that needed patient-controlled encryption plus
revocable provider access; published because the primitives don't have anything health-specific
in them. Maintained by the [Tiny Tars Foundation](https://tinytars.foundation), a 501(c)(3).

**Read `THREAT_MODEL.md` before you adopt this.** It documents what's in scope, what isn't, and
two deliberate design tradeoffs (extractable keys, no forward secrecy on revoke) that look like
bugs if you haven't read them first.

## Install

```
npm install @tars/security
```

Requires an environment with `SubtleCrypto` (`globalThis.crypto.subtle`) — every modern browser,
Node 19+, Cloudflare Workers, Deno.

## Quick start: encrypt, wrap, unwrap (Node, no Cloudflare)

This runs in plain Node 19+ — no Workers runtime, no Hono required for the crypto itself, no
`node:crypto` import either (`generateAccountKeypair`/`encryptVaultV2`/etc. read
`globalThis.crypto.subtle`, which Node provides natively). It shows the full v2 flow: generate an
account keypair, encrypt a payload under a fresh DEK, wrap that DEK for the account, then unwrap
and decrypt.

```ts
import {
  generateAccountKeypair,
  generateDEK,
  encryptVaultV2,
  wrapDEKForPublicKey,
  unwrapDEKWithPrivateKey,
  decryptVaultV2,
} from "@tars/security/crypto";

// One-time: the account's long-term keypair. In a real app the private key
// is wrapped under a KEK (see ARCHITECTURE.md) and never held like this.
const { publicKeyJwk, privateKey } = await generateAccountKeypair();

// Encrypt a payload (any JSON-serializable value) under a fresh, random DEK.
const dek = await generateDEK();
const envelope = await encryptVaultV2({ note: "patient-controlled data" }, dek);

// Grant this account access by wrapping the DEK for its public key.
const wrapped = await wrapDEKForPublicKey(dek, publicKeyJwk);

// Later, as that account: unwrap the DEK and decrypt the envelope.
const recoveredDek = await unwrapDEKWithPrivateKey(wrapped.wrappedDEK, wrapped.ephemeralPublicKeyJwk, privateKey);
const plaintext = await decryptVaultV2(envelope, recoveredDek);

console.log(plaintext); // { note: "patient-controlled data" }
```

This package ships TypeScript source directly (no compiled `dist/`) — the subpath imports above
resolve via `package.json`'s `exports` map to the `.ts` files, which works out of the box with a
bundler or TS-aware runtime (Vite, esbuild, `tsx`, Deno). Plain `node file.js` without a TS loader
won't resolve them; a compiled build is a tracked follow-up, not yet done.

## Quick start: a minimal Hono route backed by an in-memory store

`resolveEnvelopeAccess` only needs the two narrow slices of your storage it actually reads —
`EnvelopeAccessSource` (2 methods) and `ProviderLinkSource` (1 method), both exported from
`envelope-access.ts` — not the full `EnvelopeStore`/`ProviderLinkStore` contracts from `stores.ts`.
Swap the in-memory `Map`s below for a real adapter (a D1 client, Postgres, whatever you have) and
the route is unchanged.

```ts
import { Hono } from "hono";
import { resolveEnvelopeAccess } from "@tars/security/envelope-access";
import type { EnvelopeAccessSource, ProviderLinkSource } from "@tars/security/envelope-access";
import type { Envelope, ProviderLink, VaultRow } from "@tars/security/stores";

const envelopes = new Map<string, Envelope>(); // key: `${vaultId}:${principalAccountId}`
const vaults = new Map<string, VaultRow>();
const providerLinks = new Map<string, ProviderLink>(); // key: `${patientAccountId}:${providerAccountId}`

const envelopeSource: EnvelopeAccessSource = {
  async getEnvelopeRow(vaultId, principalAccountId) {
    return envelopes.get(`${vaultId}:${principalAccountId}`) ?? null;
  },
  async getVault(vaultId) {
    return vaults.get(vaultId) ?? null;
  },
};

const providerLinkSource: ProviderLinkSource = {
  async getActive(patientAccountId, providerAccountId) {
    return providerLinks.get(`${patientAccountId}:${providerAccountId}`) ?? null;
  },
};

// No "org recovery account" concept in this example — pass a value nothing will ever match.
const ORG_ACCOUNT_ID = "__none__";

const app = new Hono();

app.get("/vaults/:id", async (c) => {
  const principalAccountId = c.get("accountId"); // set by your own auth middleware
  const vaultId = c.req.param("id");

  const envelope = await resolveEnvelopeAccess(
    envelopeSource,
    providerLinkSource,
    vaultId,
    principalAccountId,
    ORG_ACCOUNT_ID,
  );
  if (!envelope) return c.json({ error: "forbidden" }, 403);

  return c.json({ envelope });
});

export default app;
```

`resolveEnvelopeAccess` never touches HTTP or session state itself — `c.get("accountId")` above
is entirely your own auth middleware's job. See `THREAT_MODEL.md`'s "trust boundaries" section.

## What's here

| Module | What it does |
|---|---|
| `kdf.ts` | Shared PBKDF2-SHA256 key derivation, runtime-agnostic |
| `bytes.ts` | One helper: safely turn a `Uint8Array` view into the `ArrayBuffer` WebCrypto wants |
| `crypto.ts` | HD1 envelope format (v1 passphrase-only, v2 DEK + multi-principal wrap), account keypairs, KEK wrapping, recovery-code grants |
| `key-store.ts` | Browser-only: persists an account's private key in IndexedDB as non-extractable |
| `vault-sink.ts` | `VaultSink` interface + a conflict-safe (ETag/If-Match) HTTP `PUT` implementation for saving an encrypted blob |
| `stores.ts` | Five storage-agnostic contracts: `AccountStore`, `CredentialStore`, `EnvelopeStore`, `ProviderLinkStore`, `AuditStore` |
| `envelope-access.ts` | `resolveEnvelopeAccess` — the one composed access-policy function built on `stores.ts` |

Full design, including the exact envelope byte layout and why extractable keys are a deliberate
choice: `ARCHITECTURE.md`. Adapters (D1, R2, a plain HTTP adapter) are a tracked follow-up, not
yet published — see `ARCHITECTURE.md`'s "Adapters" section.

## Contributing

See `CONTRIBUTING.md`. Any change to `kdf.ts` or an envelope format needs a new
`tests/kdf.test.ts` (or `tests/crypto.test.ts`) case — those are the two things every consumer's
data durability depends on.

## Tests

```
npm install
npm test        # vitest, 48 tests across 6 files, real WebCrypto — no mocked crypto
npm run typecheck
```

## License

MIT — see `LICENSE`.
