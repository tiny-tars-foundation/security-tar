# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This package follows
semver, but is pre-1.0 — expect breaking changes between minor versions until 1.0.0.

## [Unreleased]

## [0.1.0] — Initial public release

Extracted from a health-records application's internal `packages/security`. First public
version; no prior published releases.

### Added

- `kdf.ts` — shared PBKDF2-HMAC-SHA256 key derivation (200,000 iterations), runtime-agnostic.
- `crypto.ts` — HD1 envelope format: v1 (passphrase-only) and v2 (DEK-based, multi-principal
  access via ECDH-ES-wrapped keys); account keypair generation; KEK wrapping of private keys from
  either a password or a WebAuthn PRF secret; one-time recovery-code grants.
- `key-store.ts` — browser IndexedDB persistence of an account's private key as a
  non-extractable `CryptoKey`.
- `stores.ts` — five storage-agnostic contracts: `AccountStore`, `CredentialStore`,
  `EnvelopeStore`, `ProviderLinkStore`, `AuditStore`.
- `envelope-access.ts` — `resolveEnvelopeAccess`, the composed access-policy function over
  `EnvelopeStore` + `ProviderLinkStore`.
- `LICENSE` (MIT), `THREAT_MODEL.md`, `SECURITY.md`, `ARCHITECTURE.md`, `CONTRIBUTING.md`.

### Known gaps (tracked, not blocking this release)

- No published storage adapters yet (D1, R2, plain HTTP) — see `ARCHITECTURE.md`'s "Adapters"
  section.
- No forward secrecy on revoke — see `THREAT_MODEL.md`.
- No automated test suite ships in this initial release; the modules above were tested as part
  of the internal application they were extracted from. Adding a standalone `tests/` suite here
  is a near-term follow-up, tracked in the issue tracker.
