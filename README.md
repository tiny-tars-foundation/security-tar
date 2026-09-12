# `@tinytars/vault`

[![CI](https://github.com/tinytars/vault/actions/workflows/ci.yml/badge.svg)](https://github.com/tinytars/vault/actions/workflows/ci.yml)
[![Community Health](https://img.shields.io/badge/dynamic/json?url=https://api.github.com/repos/tinytars/vault/community/profile&query=$.health_percentage&suffix=%25&label=community%20health)](https://github.com/tinytars/vault/community)

A storage operator who can read what it stores hasn't encrypted the data — it's obfuscated it,
and most hand-rolled "encrypted vault" designs end up exactly there, one convenience shortcut at a
time. This package is the alternative already built: a shared key-derivation primitive, an
authenticated envelope format with multi-principal access via wrapped data-encryption keys, and
storage-agnostic contracts for the account/vault/grant data model those envelopes sit on top of —
domain-neutral by design, not health-specific code that happened to get open-sourced.

Maintained by the [Tiny Tars Foundation](https://tinytars.foundation), a 501(c)(3).

## Why

### The HIPAA-adjacent vault

This package was extracted from a health-records app built against HIPAA-adjacent constraints,
and that origin is worth stating plainly: it's a real, fully worked use case, not a footnote.
The fit is exact: the vault **owner** is the person whose record it is; a **provider** link is a
treating professional's standing access to that record; a **support** link is a colleague's
time-boxed access, handled by `break-glass.ts`'s grant/check/revoke lifecycle so a temporary
exception doesn't quietly become a permanent one.

And the fit isn't just structural — four of the package's primitives map onto four things a
HIPAA-adjacent deployment specifically needs:

#### Satisfies the FTC Health Breach Notification Rule

The audit log in `adapters/d1/audit.ts` is shaped to satisfy the Rule's disclosure-logging
requirement directly — who accessed whose record and why, so a breach can be scoped to affected
individuals.

#### Zero-knowledge storage

`crypto.ts` gives that app a zero-knowledge vault — the storage operator holds ciphertext and
never a key or usable plaintext, which matters when the payload is a medical record.

#### Consent-based sharing

`envelope-access.ts` gives it consent-based sharing — access is a per-principal, revocable
wrapped-key grant, not a shared secret or a role flag, which is what "the record's owner controls
who sees it" actually requires at the implementation level.

#### Time-boxed emergency access

`break-glass.ts` gives it the piece hand-rolled HIPAA-adjacent systems get wrong most often: a
time-boxed grant with the TTL clamp, self-expiry, and audit trail built in.

None of this makes the package itself HIPAA-compliant — it's a primitive an adopter builds
compliant handling on top of, not a compliance product in its own right — but the shape it ships
is exactly the shape that adopter needs, not something assembled from unrelated parts after the
fact.

### Beyond health

The same three primitives — an encrypted resource only its owner can read by default, a revocable
per-principal grant, and a time-boxed version of that grant — solve an identical problem anywhere
one party owns sensitive data and needs to hand a second party temporary or standing access to it,
under a record of who saw what and when. None of `stores.ts`'s contracts, `crypto.ts`'s envelope
format, or `break-glass.ts`'s lifecycle reference anything about the payload's shape or domain.
Concretely, beyond the healthcare case above:

- **Outside counsel** reviewing a client's encrypted case files, access granted for the matter's
  duration and revoked when it closes.
- **An accountant** getting temporary access to a household's financial records at tax time,
  through the same time-boxed grant `break-glass.ts` gives a treating professional.
- **A corporate IT admin** granted standing access to an employee's HR file for the audit trail
  it creates, or temporary access during an offboarding review.
- **A SaaS support agent** getting time-boxed access to a customer's account data to debug a
  ticket, auto-expiring instead of depending on someone remembering to revoke it.

Claims like these are only worth as much as the threat model backing them. **Read
`THREAT_MODEL.md` before you adopt this** — it documents what's in scope, what isn't, and two
deliberate design tradeoffs (extractable keys, no forward secrecy on revoke) that look like bugs
if you haven't read them first. It's written in the same domain-neutral vocabulary as the rest of
this package — no health-specific language anywhere in it. That's not an oversight; it's the same
evidence the argument above rests on, stated a second way.

## What it does

Five pieces, each independently usable — nothing here requires adopting all five.

```
                          your app
                             |
                             |  imports core modules only
                             v
   --------------------------------------------------------------
    @tinytars/vault (core) -- zero Cloudflare/platform imports

    crypto.ts + kdf.ts        zero-knowledge envelope encryption
    envelope-access.ts        consent-based access sharing
    break-glass.ts            time-boxed access grants
    stores.ts                 storage-agnostic contracts
   --------------------------------------------------------------
                             |  implements stores.ts's five contracts
                             v
   --------------------------------------------------------------
    adapters/*  (optional, subpath exports)
    d1 . r2 . memory . pages-http . conformance
   --------------------------------------------------------------
```

### Zero-knowledge vault encryption

`crypto.ts` + `kdf.ts`: an authenticated envelope format (HD1) where the storage operator holds
ciphertext and never a key or usable plaintext. Two versions — v1 is passphrase-only; v2 separates
encrypting the data from granting access to it, via per-principal wrapped data-encryption keys.
Full byte layout and the tradeoffs behind it:
[`ARCHITECTURE.md` § Envelope format](ARCHITECTURE.md#envelope-format-cryptots).

### Consent-based access sharing

`envelope-access.ts`: access to a vault is a per-principal, revocable wrapped-key grant, composed
from storage-agnostic contracts rather than baked into either one — and it closes a specific bug
class along the way, expiry checked lazily per-route instead of once, centrally. This is one of
two forms a grant takes — see [`ARCHITECTURE.md` § Principal
model](ARCHITECTURE.md#principal-model) for both. Details:
[`ARCHITECTURE.md` § Access policy](ARCHITECTURE.md#access-policy-envelope-accessts).

### Time-boxed break-glass access

`break-glass.ts`: temporary access that's actually temporary — a TTL clamp, self-expiry on next
check rather than on a timer, idempotent revoke, and an audit trail, so an exception doesn't
quietly become a standing grant nobody remembers to close. It's the time-boxed form of the same
grant described above, not a separate mechanism — see [`ARCHITECTURE.md` § Principal
model](ARCHITECTURE.md#principal-model). Details:
[`ARCHITECTURE.md` § Time-boxed access grants](ARCHITECTURE.md#time-boxed-access-grants-break-glassts).

### Storage-agnostic contracts

`stores.ts` + `blob-store.ts`: five plain data-access interfaces — accounts, credentials,
envelopes, grants, audit log — plus a generic conditional-write blob interface, none of them
carrying crypto or policy. An adapter (D1, Postgres, an in-memory map) implements these against
whatever it stores rows in; the crypto and access-policy layers above never know which one is
underneath. Details:
[`ARCHITECTURE.md` § Storage contracts](ARCHITECTURE.md#storage-contracts-storests).

### Platform-independent adapters

`adapters/*`: everything above — `crypto.ts`, `kdf.ts`, `stores.ts`, `envelope-access.ts`,
`break-glass.ts`, and the rest — has zero Cloudflare (or any other platform) imports. An adopter
who never imports `@tinytars/vault/adapters/*` never links against Cloudflare's types at all —
that's the actual mechanism behind "platform-independent," not a claim about intent. Five adapters
ship as optional subpath exports for adopters who do want one: `adapters/d1` and `adapters/r2`
(Cloudflare), `adapters/memory` (the portability proof — the same conformance suite that passes
against the D1 adapter passes against it, unmodified), and `adapters/pages-http` (a five-line
wrapper, not a rewrite, for Cloudflare Pages Functions' request shape). Full picture:
[`ARCHITECTURE.md` § Adapters](ARCHITECTURE.md#adapters).

### Reference client: auth flows wired to a real API

`auth-client.ts`, `auth-recovery.ts`, `auth-support.ts`, `auth-grants.ts`, and `org-recovery.ts`:
browser-side orchestration for signup, password/passkey login, Google SSO bootstrap, recovery-code
issuance and redemption, provider/support access grants, and account-settings method management —
built on `crypto.ts`'s primitives, calling a specific set of `/api/auth/*`, `/api/account/*`,
`/api/support/*`, and `/api/providers/*` routes. `vault-session.ts` holds the `VaultEntry`/
`VaultSession` types and `openVault()` these flows share to open a decrypted vault once a key is in
hand.

Unlike the four pieces above, this layer is a **reference implementation, not a portable
primitive** — it's wired to one server API shape (documented in
[`ARCHITECTURE.md` § Reference auth client](ARCHITECTURE.md#reference-auth-client-auth-clientts-and-friends)),
the same way `vault-sink.ts`'s `r2Sink`/`localSink` are wired to specific save-vault routes. Read
it as a worked example of composing `crypto.ts` into real signup/login/recovery/support flows, not
something you import and point at your own backend unless your routes happen to match.

## Install

```
npm install @tinytars/vault
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
} from "@tinytars/vault/crypto";

// One-time: the account's long-term keypair. In a real app the private key
// is wrapped under a KEK (see ARCHITECTURE.md) and never held like this.
const { publicKeyJwk, privateKey } = await generateAccountKeypair();

// Encrypt a payload (any JSON-serializable value) under a fresh, random DEK.
const dek = await generateDEK();
const envelope = await encryptVaultV2({ note: "owner-controlled data" }, dek);

// Grant this account access by wrapping the DEK for its public key.
const wrapped = await wrapDEKForPublicKey(dek, publicKeyJwk);

// Later, as that account: unwrap the DEK and decrypt the envelope.
const recoveredDek = await unwrapDEKWithPrivateKey(wrapped.wrappedDEK, wrapped.ephemeralPublicKeyJwk, privateKey);
const plaintext = await decryptVaultV2(envelope, recoveredDek);

console.log(plaintext); // { note: "owner-controlled data" }
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
import { resolveEnvelopeAccess } from "@tinytars/vault/envelope-access";
import type { EnvelopeAccessSource, ProviderLinkSource } from "@tinytars/vault/envelope-access";
import type { Envelope, ProviderLink, VaultRow } from "@tinytars/vault/stores";

const envelopes = new Map<string, Envelope>(); // key: `${vaultId}:${principalAccountId}`
const vaults = new Map<string, VaultRow>();
const providerLinks = new Map<string, ProviderLink>(); // key: `${ownerAccountId}:${providerAccountId}`

const envelopeSource: EnvelopeAccessSource = {
  async getEnvelopeRow(vaultId, principalAccountId) {
    return envelopes.get(`${vaultId}:${principalAccountId}`) ?? null;
  },
  async getVault(vaultId) {
    return vaults.get(vaultId) ?? null;
  },
};

const providerLinkSource: ProviderLinkSource = {
  async getActive(ownerAccountId, providerAccountId) {
    return providerLinks.get(`${ownerAccountId}:${providerAccountId}`) ?? null;
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
| `break-glass.ts` | `grantBreakGlass`/`checkBreakGlass`/`revokeBreakGlass` — time-boxed grants: TTL clamp, expiry self-revoke, idempotent revoke, all audited |
| `blob-store.ts` | `BlobStore` — a generic, conditional-write ("only if unchanged") interface for storing an opaque encrypted blob by key. Server-side counterpart to `vault-sink.ts`'s browser-side `VaultSink` |
| `adapters/d1/` | `D1AccountStore`/`D1CredentialStore`/`D1EnvelopeStore`/`D1ProviderLinkStore`/`D1AuditStore` — a Cloudflare D1 implementation of all five `stores.ts` contracts |
| `adapters/r2.ts` | `R2BlobStore` — a Cloudflare R2 implementation of `BlobStore` |
| `adapters/memory.ts` | In-memory implementations of all five `stores.ts` contracts — the reference adapter that proves the interfaces are actually storage-agnostic, not just Cloudflare-shaped |
| `adapters/pages-http.ts` | `pagesHandler()` — wraps a portable `(request, deps) => Promise<Response>` handler into Cloudflare Pages Functions' `onRequestX({request, env, params})` shape |
| `adapters/conformance.ts` | Shared vitest contract suites for each `stores.ts` interface, run against every adapter above so "storage-agnostic" is proven, not asserted |
| `auth-client.ts` | Password/passkey/Google signup, login, session resume, account-settings method management — the browser-side orchestration wiring `crypto.ts` to a specific `/api/auth/*`/`/api/account/*` API. Reference client, not a portable primitive |
| `auth-recovery.ts` | Recovery-code issuance/redemption (owner and provider-issued), DEK rotation, access-event log fetch — same reference-client caveat as `auth-client.ts` |
| `auth-support.ts` | Audited support-agent access: owner approves a pending request, support enters via an audited endpoint; support→provider roster access |
| `auth-grants.ts` | Provider grant CRUD from the owner side: lookup, grant, revoke |
| `org-recovery.ts` | Backfills the org-recovery envelope for accounts that predate or missed it at signup — best-effort, never blocks an unlock |
| `vault-session.ts` | `VaultEntry`/`VaultSession` types plus `openVault()` — the decrypt-and-open-session step every unlock path shares |
| `base64.ts` | Byte ↔ base64 codec used throughout the client layer |

Full design, including the exact envelope byte layout and why extractable keys are a deliberate
choice, is in `ARCHITECTURE.md` — see **What it does** above for the featureset summary and the
platform-independence mechanism behind the adapters.

## Contributing

See `CONTRIBUTING.md`. Any change to `kdf.ts` or an envelope format needs a new
`tests/kdf.test.ts` (or `tests/crypto.test.ts`) case — those are the two things every consumer's
data durability depends on.

## Tests

```
npm install
npm test        # vitest, 85 tests across 9 files, real WebCrypto — no mocked crypto
npm run typecheck
```

## License

MIT — see `LICENSE`.
