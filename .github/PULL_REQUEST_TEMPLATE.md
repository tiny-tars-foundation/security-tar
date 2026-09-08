## What changed and why

## Checklist

- [ ] Read [CONTRIBUTING.md](../CONTRIBUTING.md) and, if this touches `kdf.ts` or an envelope
      format (`HD1`/DEK framing in `crypto.ts`), added a new test case to `tests/kdf.test.ts` or
      `tests/crypto.test.ts` demonstrating backward compatibility or correct version-gating.
- [ ] If this "fixes" a documented tradeoff in [THREAT_MODEL.md](../THREAT_MODEL.md) (extractable
      DEKs/private keys, no forward secrecy on revoke, PBKDF2 instead of Argon2id), updated
      `THREAT_MODEL.md` to explain the new tradeoff rather than silently changing it.
- [ ] `npm test` and `npm run typecheck` pass locally.
