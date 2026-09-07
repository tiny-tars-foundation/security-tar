# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This package follows
semver, but is pre-1.0 — expect breaking changes between minor versions until 1.0.0.

## [Unreleased]

## [0.1.0] — Initial public release

Extracted from a health-records application's internal `packages/security`. First public
version; no prior published releases.

### Added

- `kdf.ts` — shared PBKDF2-HMAC-SHA256 key derivation (200,000 iterations), runtime-agnostic.
- `bytes.ts` — `toArrayBuffer`, a `byteOffset`-safe conversion from a `Uint8Array` view to the
  `ArrayBuffer` WebCrypto calls want.
- `crypto.ts` — HD1 envelope format: v1 (passphrase-only) and v2 (DEK-based, multi-principal
  access via ECDH-ES-wrapped keys); account keypair generation; KEK wrapping of private keys from
  either a password or a WebAuthn PRF secret; one-time recovery-code grants.
- `key-store.ts` — browser IndexedDB persistence of an account's private key as a
  non-extractable `CryptoKey`.
- `vault-sink.ts` — `VaultSink` interface plus a conflict-safe (ETag/`If-Match`) HTTP `PUT`
  implementation, with per-vault write serialization and a typed `VaultConflictError`.
- `stores.ts` — five storage-agnostic contracts: `AccountStore`, `CredentialStore`,
  `EnvelopeStore`, `ProviderLinkStore`, `AuditStore`.
- `envelope-access.ts` — `resolveEnvelopeAccess`, the composed access-policy function over
  `EnvelopeStore` + `ProviderLinkStore`.
- `break-glass.ts` — `grantBreakGlass`/`checkBreakGlass`/`revokeBreakGlass`: time-boxed access
  grants over `ProviderLinkStore`/`AuditStore`/`EnvelopeStore` — TTL clamp to a policy max,
  expiry that self-revokes and audits, idempotent revoke.
- `LICENSE` (MIT), `THREAT_MODEL.md`, `SECURITY.md`, `ARCHITECTURE.md`, `CONTRIBUTING.md`.
- `tests/` — a vitest suite (57 tests across 7 files) covering every module above: KDF
  determinism and parameters, both envelope format versions and their cross-rejection, KEK
  wrapping from a password and from a passkey PRF secret, the key-store non-extractability
  guarantee, `vault-sink`'s conflict/serialization behavior, `bytes.ts`'s `byteOffset` handling,
  `resolveEnvelopeAccess`'s owner/org-recovery/provider-link decision paths, and
  `break-glass.ts`'s TTL-clamp/expiry/idempotent-revoke logic.

### Known gaps (tracked, not blocking this release)

- No published storage adapters yet (D1, R2, plain HTTP) — see `ARCHITECTURE.md`'s "Adapters"
  section.
- No forward secrecy on revoke — see `THREAT_MODEL.md`.
