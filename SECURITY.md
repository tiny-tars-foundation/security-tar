# Security policy

## Reporting a vulnerability

Email **contact@tinytars.foundation** with a description of the issue and, if you have one, a
minimal reproduction. Please don't open a public issue for a suspected vulnerability until it's
been triaged.

We aim to acknowledge reports within 5 business days. There is no bug bounty; this is a
volunteer-maintained package from a 501(c)(3).

## Scope

In scope: `kdf.ts`, `crypto.ts`, `key-store.ts`, `stores.ts`, `envelope-access.ts`, and any
adapter shipped from this repository (`adapters/*`, once published).

Out of scope: vulnerabilities in an adopter's own use of this package that fall outside the
guarantees documented in `THREAT_MODEL.md` (for example, an adopter exposing a `Store` method to
an unauthenticated caller). Read `THREAT_MODEL.md` first — several things that look like bugs
(extractable keys, no forward secrecy on revoke) are documented, deliberate tradeoffs, not
unknown issues.

## Supported versions

Only the latest published minor version receives security fixes, per `CHANGELOG.md`. This
package is pre-1.0; expect breaking changes between minor versions until 1.0.0.
