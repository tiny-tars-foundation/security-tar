# Architecture

`@tars/security` has three layers. Lower layers know nothing about higher ones — `kdf.ts`
never imports from `crypto.ts`, and neither imports from `stores.ts` or `envelope-access.ts`.

```
kdf.ts              shared key derivation primitive
crypto.ts            key-store.ts       envelope format + keypair/DEK logic (browser-only persistence)
stores.ts             storage-agnostic contracts (no crypto, no policy)
envelope-access.ts    one composed access-policy function, built on stores.ts
```

## Key derivation (`kdf.ts`)

One derivation function, shared by every envelope format that needs a password-derived key:

- **PBKDF2-HMAC-SHA256**, `200_000` iterations.
- 16-byte random salt (`SALT_LEN`), 12-byte random IV (`IV_LEN`) for the AES-GCM layer that
  consumes the derived key.
- Runtime-agnostic: `SubtleCrypto` is passed in as a parameter, not read off a global. This is
  what lets the same module run in a browser, a Cloudflare Worker, and Node's `crypto.webcrypto`
  without a shim.

200,000 iterations is an OWASP-floor PBKDF2 parameter, not an Argon2id-class one — this package
does not implement Argon2id. If you need memory-hard derivation, derive your own key upstream and
hand this module raw key bytes, or don't use this module for that path. See `THREAT_MODEL.md` for
why this tradeoff was made and what upgrading it would require (a version byte, since existing
ciphertext blobs don't carry an iteration count).

**`kdf.ts` is intentionally the only shared surface between envelope formats.** Two independent
envelope formats exist in this codebase's history (`EB1`, `HD1`); they share this derivation and
nothing else. Do not merge their framing code — that has been proposed before and is wrong: the
formats evolve on different schedules and a shared frame couples them for no benefit.

## Envelope format (`crypto.ts`)

### HD1 v1 — passphrase-only

```
MAGIC(3, "HD1") | VERSION(1)=1 | salt(16) | iv(12) | ciphertext
```

Passphrase → PBKDF2 (`kdf.ts`) → AES-GCM-256 key → encrypts the payload directly. One
passphrase, one key, no access control beyond "do you know the passphrase."

### HD1 v2 — DEK-based, multi-principal

```
MAGIC(3) | VERSION(1)=2 | vaultKeyId(16) | iv(12) | ciphertext
```

Same 32-byte header length as v1, deliberately — code that only checks magic + total length
without branching on version stays correct.

v2 separates *encrypting the data* from *granting access to it*:

1. A random per-vault **DEK** (data encryption key) encrypts the payload with AES-GCM.
2. The DEK itself is wrapped, once per principal who should be able to read the vault, via
   ECDH-ES: an ephemeral P-256 keypair does ECDH against the principal's long-term public key,
   and the resulting shared secret wraps the DEK with AES-GCM. This is functionally equivalent
   to JWE's `ECDH-ES+A256GCM`.
3. "Grant access to principal X" = wrap the same DEK again for X's public key. No secret is
   shared between principals, and revoking one principal's *future* access means deleting their
   wrapped-DEK row — it does not touch anyone else's.

`vaultKeyId` is an opaque reference into the caller's own storage (a row ID, not key material)
— resolving it to an actual wrapped DEK is the storage layer's job, not this module's.

### Account keypairs and the KEK

Each account holds a long-term ECDH P-256 keypair (`generateAccountKeypair`). The private key is
never stored raw — it's wrapped under a KEK (key-encryption key) with AES-GCM
(`wrapPrivateKey`/`unwrapPrivateKey`, operating on PKCS8 bytes). The KEK itself comes from one of
two sources, both producing an AES-GCM key of the same shape:

- **Password-derived** (`deriveKekFromPassword`) — same PBKDF2 parameters as `kdf.ts`.
- **WebAuthn PRF secret** (`kekFromPrfSecret`) — the authenticator's PRF extension output is
  imported directly as an AES-GCM key, no PBKDF2 step. This is what lets a passkey unlock the
  account without a password ever existing.

`deriveAuthHash()` produces a server-verifiable value from the same password, domain-separated
from the KEK derivation by appending `"|auth"` to the salt before the PBKDF2 call. A server can
verify a login (`SHA-256(authHash)` stored server-side) without ever learning the password or the
KEK it derives.

### Recovery-code grants (`wrapDEKWithKek`/`unwrapDEKWithKek`)

A one-time recovery mechanism: wrap a DEK under a KEK derived from a recovery code (same
AES-GCM shape as everything else here). **The wrapped blob must be deleted the moment the grant
is consumed.** AES-GCM's authentication tag lets a holder of the ciphertext verify whether a
*guessed* code was correct without needing to fully decrypt anything meaningful — leaving the
blob in place after use turns it into an online guessing oracle against the recovery code.

### Extractability is a deliberate choice, not an oversight

Keys and DEKs unwrapped by this module are `extractable`. That is intentional: an authorized
holder needs to be able to re-wrap a DEK for a newly added principal, or re-wrap a private key
under a new KEK when a login method is added. This is the same trust boundary as holding a
session DEK in memory at all — see `THREAT_MODEL.md`.

## Browser key persistence (`key-store.ts`)

The only browser-specific module in this package (everything else is runtime-agnostic). Persists
an account's unwrapped ECDH private key in IndexedDB as a **non-extractable**, structured-cloned
`CryptoKey`. The point: code running on the page (including an XSS payload) can ask the browser
to *use* the key — sign, derive, unwrap — but cannot ask the browser to hand back the raw key
bytes. This narrows what an XSS foothold can do with the persisted key without eliminating it;
see `THREAT_MODEL.md` for the boundary this actually draws.

## Storage contracts (`stores.ts`)

Five interfaces, each a plain data-access contract with no crypto and no policy baked in. An
adapter (D1, Postgres, an in-memory map for tests) implements these against whatever it stores
rows in:

- **`AccountStore`** — accounts, identities, session lifecycle, profile/tombstone state.
- **`CredentialStore`** — login credentials, kept separate from `AccountStore` rather than folded
  into it, because a store implementation may back credentials with a different table or a
  different backend (e.g. a WebAuthn authenticator registry) than the account row itself.
- **`EnvelopeStore`** — vault rows and their envelopes, pure storage: get/put an envelope by
  vault ID, nothing about who's allowed to.
- **`ProviderLinkStore`** — grants between principals (a "provider" linked to a "patient", in the
  vocabulary this package's first adopter uses — read it generically as "grantee linked to
  vault owner").
- **`AuditStore`** — append-only access-event logging, read back by subject.

None of these five types know about each other. Composing them into a policy is a separate,
explicit step — see below.

## Access policy (`envelope-access.ts`)

`resolveEnvelopeAccess(envelopes, providers, vaultId, principalAccountId, orgAccountId)` is the
one place this package makes an access decision, and it does so by composing `EnvelopeStore` and
`ProviderLinkStore` rather than embedding policy inside either contract:

1. The vault's owner may always access it.
2. A designated "org recovery" principal may access it, unless that vault's
   `orgRecoveryRevokedAt` is set.
3. Anyone else needs an active `ProviderLink` (`getActive`) to that vault.

This function exists specifically to fix a bug class: **expiry checked lazily, per-route, is a
bug.** A grant that a route only re-validates when it's used lets a grantee who never triggers
the self-revoking endpoint keep reading past the grant's real expiry. Composing the check once,
here, means every caller gets the same answer regardless of which route asks. Adopters without an
"org recovery" concept can ignore that branch or pass an `orgAccountId` that never matches.

**Known limitation, stated plainly:** revoking a `ProviderLink` stops the *next* read — it does
not invalidate a DEK a grantee already unwrapped and is holding in memory or in their own storage
(see the extractability note above; the same "authorized holder can re-wrap" property that makes
key rotation *possible* also means old access isn't retroactively erased just by deleting the
grant row). Forward secrecy on revoke requires DEK rotation, which this package does not yet
implement. See `THREAT_MODEL.md`.

## Adapters

No storage adapter ships in this repository yet. `stores.ts` is designed so a Cloudflare D1
adapter, an R2 blob adapter for large envelopes, and a plain HTTP/Pages Functions adapter can each
live as a subpath export (`@tars/security/adapters/d1`, etc.) without pulling Cloudflare-specific
types into the core package. That work is tracked as a near-term follow-up, not bundled into this
initial release — see the repository's issue tracker.
