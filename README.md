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

This runs in plain Node — no Workers runtime, no Hono required for the crypto itself. It shows
the full v2 flow: generate an account keypair, encrypt a payload under a fresh DEK, wrap that
DEK for the account, then unwrap and decrypt.

```ts
import { webcrypto } from "node:crypto";
import {
  generateAccountKeypair,
  encryptWithDEK,
  wrapDEKForPublicKey,
  unwrapDEKWithPrivateKey,
  decryptWithDEK,
} from "@tars/security/crypto";

const subtle = webcrypto.subtle;

// One-time: the account's long-term keypair. In a real app the private key
// is wrapped under a KEK (see ARCHITECTURE.md) and never held like this.
const { publicKey, privateKey } = await generateAccountKeypair(subtle);

// Encrypt a payload under a fresh, random DEK.
const payload = new TextEncoder().encode(JSON.stringify({ note: "patient-controlled data" }));
const { dek, envelope } = await encryptWithDEK(subtle, payload);

// Grant this account access by wrapping the DEK for its public key.
const wrapped = await wrapDEKForPublicKey(subtle, dek, publicKey);

// Later, as that account: unwrap the DEK and decrypt the envelope.
const recoveredDek = await unwrapDEKWithPrivateKey(subtle, wrapped, privateKey);
const plaintext = await decryptWithDEK(subtle, envelope, recoveredDek);

console.log(new TextDecoder().decode(plaintext)); // { "note": "patient-controlled data" }
```

## Quick start: a minimal Hono route backed by an in-memory store

Shows the storage contract from `stores.ts` and the access-policy composition from
`envelope-access.ts` wired into an HTTP route, with no Cloudflare-specific code — swap the
in-memory `Map`s for a real `EnvelopeStore`/`ProviderLinkStore` implementation (a D1 adapter,
Postgres, whatever you have) and the route is unchanged.

```ts
import { Hono } from "hono";
import { resolveEnvelopeAccess } from "@tars/security/envelope-access";
import type { EnvelopeStore, ProviderLinkStore } from "@tars/security/stores";

const envelopes = new Map(); // vaultId -> Envelope
const providerLinks = new Map(); // vaultId -> ProviderLink[]

const envelopeStore: EnvelopeStore = {
  async getEnvelopeRow(vaultId) {
    return envelopes.get(vaultId) ?? null;
  },
  // ...the rest of EnvelopeStore, backed by the same in-memory Map.
};

const providerLinkStore: ProviderLinkStore = {
  async getActive(vaultId, principalAccountId) {
    return (providerLinks.get(vaultId) ?? []).find(
      (link) => link.granteeAccountId === principalAccountId && link.status === "active",
    ) ?? null;
  },
  // ...the rest of ProviderLinkStore.
};

const app = new Hono();

app.get("/vaults/:id", async (c) => {
  const principalAccountId = c.get("accountId"); // set by your own auth middleware
  const vaultId = c.req.param("id");

  const allowed = await resolveEnvelopeAccess(
    envelopeStore,
    providerLinkStore,
    vaultId,
    principalAccountId,
    /* orgAccountId */ undefined,
  );
  if (!allowed) return c.json({ error: "forbidden" }, 403);

  const envelope = await envelopeStore.getEnvelopeRow(vaultId);
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
| `crypto.ts` | HD1 envelope format (v1 passphrase-only, v2 DEK + multi-principal wrap), account keypairs, KEK wrapping, recovery-code grants |
| `key-store.ts` | Browser-only: persists an account's private key in IndexedDB as non-extractable |
| `stores.ts` | Five storage-agnostic contracts: `AccountStore`, `CredentialStore`, `EnvelopeStore`, `ProviderLinkStore`, `AuditStore` |
| `envelope-access.ts` | `resolveEnvelopeAccess` — the one composed access-policy function built on `stores.ts` |

Full design, including the exact envelope byte layout and why extractable keys are a deliberate
choice: `ARCHITECTURE.md`. Adapters (D1, R2, a plain HTTP adapter) are a tracked follow-up, not
yet published — see `ARCHITECTURE.md`'s "Adapters" section.

## Contributing

See `CONTRIBUTING.md`. Any change to `kdf.ts` or an envelope format needs a new
`shared-kdf.test.ts` case — those are the two things every consumer's data durability depends on.

## License

MIT — see `LICENSE`.
