# Contributing

## Before you open a PR

Read `THREAT_MODEL.md`. A number of things in this package that look like bugs at a glance —
extractable DEKs and private keys, no forward secrecy on revoke, PBKDF2 instead of Argon2id — are
documented, deliberate tradeoffs. If your PR "fixes" one of those, it needs to either update
`THREAT_MODEL.md` to explain the new tradeoff, or it's solving a problem this package has already
decided not to solve at this layer.

## Changes to `kdf.ts` or an envelope format require a new test case

Every consumer's already-encrypted data depends on `kdf.ts`'s parameters and each envelope
format's byte layout staying stable, or on version bytes correctly distinguishing old data from
new. **A PR touching `kdf.ts`, or the `HD1`/DEK envelope framing in `crypto.ts`, must add a new
case to `tests/kdf.test.ts` (or `tests/crypto.test.ts` for envelope framing) demonstrating the
change is either backward-compatible or correctly version-gated.** A PR without that test case will be
asked to add one before merge, no exceptions — this is the one place in the package where "it
passed the existing tests" isn't sufficient, because the existing tests were written before your
change and can't know to check for it.

## Don't merge the two envelope formats

`kdf.ts` is deliberately the *only* thing shared between independent envelope formats in this
package's history. If a PR proposes unifying envelope framing to reduce duplication, read the
comment at the top of `kdf.ts` first — this has been proposed before and rejected for a documented
reason: the formats evolve on independent schedules, and a shared frame couples them with no
compensating benefit.

## Style

- No comments explaining *what* code does — name things so the code reads on its own. A comment
  earns its place only by explaining a non-obvious *why* (a hidden constraint, a workaround, an
  invariant a reader could otherwise violate by "fixing" the code).
- No dependencies beyond what's already here without discussion first — this package's value is
  partly that it's small enough to audit in one sitting.
- Tests hit real implementations (real `SubtleCrypto`, an in-memory store implementing the real
  contract), not mocks, unless there's no other option.

## Reporting a security issue instead of filing a PR

See `SECURITY.md` — vulnerabilities go to contact@tinytars.foundation, not a public issue or PR,
until triaged.
