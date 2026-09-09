# Threat model

This document says what `@tinytars/vault` protects against, what it deliberately does not, and
where the trust boundaries sit. Read it before adopting the package, and especially before
building a storage adapter for it — the adapter inherits these boundaries, it doesn't get to
redraw them.

## What this package is

A set of pure cryptographic primitives (`kdf.ts`, `crypto.ts`), one browser-only key-persistence
helper (`key-store.ts`), a set of storage-agnostic data contracts (`stores.ts`), one composed
access-policy function (`envelope-access.ts`), and a reference client layer (`auth-client.ts`,
`auth-recovery.ts`, `auth-support.ts`, `auth-grants.ts`, `org-recovery.ts`, `vault-session.ts`)
that composes those primitives into worked signup/login/recovery/support-access/grant flows
against one specific server API shape. See `ARCHITECTURE.md` for how they fit together, and "Not a
portable client SDK" below before treating the reference client as a drop-in for your own backend.

## What this package is NOT

- **Not a transport-security layer.** TLS between client and server is assumed, not provided.
  Nothing here defends against a network attacker who can also break TLS.
- **Not an authentication system.** `deriveAuthHash()` gives you a value a server can verify
  without learning the password, but issuing sessions, checking them on each request, and
  deciding whether a caller is who they claim to be is entirely the adopter's job. The reference
  client layer (`auth-client.ts` and friends) orchestrates signup/login/recovery calls and unwraps
  the resulting keys client-side, but it does not change this: session issuance and verification
  stay server-side, and the API it calls is a worked example, not a contract this package
  implements or enforces on your server.
- **Not a portable client SDK.** `auth-client.ts`/`auth-recovery.ts`/`auth-support.ts`/
  `auth-grants.ts` call a specific set of `/api/auth/*`, `/api/account/*`, `/api/support/*`,
  `/api/providers/*`, and `/api/vault/*` routes that this package does not implement or specify as
  a contract — they show how the primitives above compose into real flows, not something you
  import and point at an arbitrary backend. `vault-sink.ts`'s `r2Sink`/`localSink` already carry
  this same caveat for save-vault routes; see `ARCHITECTURE.md`'s "Reference auth client" section.
- **Not rate-limiting or brute-force protection.** Nothing here throttles passphrase or
  recovery-code guesses. An adopter must rate-limit any endpoint that accepts one.
- **Not the storage backend's access control.** D1's, Postgres's, or R2's own IAM/ACL layer is
  out of scope; this package assumes whatever calls a `Store` interface is already authorized to
  make that call at the transport/session layer.
- **Not a UI.** No consent screens, no key-ceremony flows — those are the adopter's.

## In scope: what's actually being defended

### The KDF parameter choice

PBKDF2-HMAC-SHA256 at 200,000 iterations (`kdf.ts`) is an OWASP-floor choice, not a
memory-hard one. It defends against offline dictionary/brute-force attacks on a leaked envelope
at a level appropriate for a password with reasonable entropy, but it is weaker than Argon2id
against a well-resourced attacker with custom ASIC/GPU hardware. This was a deliberate tradeoff
for portability across runtimes that don't all expose Argon2id via `SubtleCrypto`, not an
oversight. **If your threat model requires memory-hard derivation, derive the key upstream of
this package.** Raising the iteration count later requires a version byte in the envelope format,
because existing ciphertext doesn't carry its iteration count — this is a known, not-yet-taken
upgrade path.

### Envelope format confusion

The magic bytes + version byte at the front of every HD1 envelope exist specifically so a v1
blob can never be misinterpreted as v2 (or vice versa) by code that forgets to check the version.
`bytes.ts`'s helpers enforce fixed-length reads so a truncated or corrupted blob fails a length
check rather than silently decrypting garbage.

### Key extractability — read this before you audit the code

DEKs and unwrapped private keys produced by `crypto.ts` are marked `extractable: true` in
`SubtleCrypto` terms. **This is deliberate, not a bug**, and it is the single most
audit-worth design decision in this package:

- It's what lets an authorized holder re-wrap a DEK for a newly granted principal, or re-wrap a
  private key under a new KEK when a user adds a passkey.
- It means: **if an attacker achieves code execution in a context that already holds an
  unwrapped DEK or private key (e.g. an XSS payload running in a page mid-session), they can
  exfiltrate that key material.** This package does not defend against that scenario for
  in-memory session keys — it accepts it as the same trust boundary as "code running on this
  page can already act as this user for as long as the session lasts."
- `key-store.ts` narrows this for the one case it covers: the account's long-term private key,
  at rest in IndexedDB, is persisted as `extractable: false`. An XSS payload running against a
  page that later opens that IndexedDB store can *use* the key (sign, unwrap) but cannot pull
  the raw bytes back out. This does not protect the key *while it is unwrapped and held in an
  active session* — only the at-rest copy.

If your deployment's threat model includes "assume XSS happens," treat every unwrapped key held
during an active session as compromised for that session's duration, and design session lifetime
and re-authentication accordingly. This package gives you the primitives to rotate keys and
re-grant access after such an event — it does not detect or prevent the event itself.

### Recovery-code oracle risk

`wrapDEKWithKek`/`unwrapDEKWithKek` (used for one-time recovery-code grants) rely on the caller
deleting the wrapped blob immediately after a successful unwrap. AES-GCM's authentication tag
lets anyone holding the ciphertext test a guessed code for correctness without a full valid
decrypt round-trip elsewhere in the system. **An adapter that doesn't delete the blob on
consumption reintroduces an online guessing oracle against the recovery code**, regardless of how
strong the code itself is. This is an adapter responsibility, not something the primitive can
enforce on its own.

### No forward secrecy on revoke (yet)

`resolveEnvelopeAccess` correctly stops a revoked principal's *next* access attempt — see
`ARCHITECTURE.md` for the bug class it was built to close (lazy, per-route expiry checks). It does
**not** invalidate a DEK that principal already unwrapped before revocation. A principal who
cached the DEK client-side, or wrote it down, still has it. Closing that gap requires DEK
rotation (re-encrypting the payload under a fresh DEK and re-wrapping only for the principals who
should still have access), which this package does not yet implement. Treat "revoke" as "stop
future access," not "guarantee the data is unreadable to that principal going forward."

## Trust boundaries per store interface

Every method on `AccountStore`, `CredentialStore`, `EnvelopeStore`, `ProviderLinkStore`, and
`AuditStore` assumes its caller is already authenticated and authorized to make that specific
call — these are data-access contracts, not authorization checkpoints. `resolveEnvelopeAccess` is
the one place in this package that makes an authorization decision, and it in turn assumes its
`principalAccountId` argument has already been established by the adopter's own session/auth
layer. **Do not expose any `Store` method directly to an unauthenticated caller** — every route
that calls one must authenticate and authorize first, using its own session mechanism, before
this package's code ever runs.

## Reporting a vulnerability

See `SECURITY.md`.
