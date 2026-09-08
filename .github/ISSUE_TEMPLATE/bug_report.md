---
name: Bug report
about: Something in @tinytars/vault isn't behaving as documented
title: ""
labels: bug
---

**Describe the bug**
A clear description of what's wrong, including which module (`crypto.ts`, `kdf.ts`,
`envelope-access.ts`, `break-glass.ts`, `stores.ts`, or an adapter) is involved.

**To reproduce**
Minimal steps or a code snippet that triggers it.

**Expected behavior**
What you expected to happen instead.

**Environment**
- @tinytars/vault version:
- Runtime (Node / Cloudflare Workers / Deno) and version:

**Is this a security vulnerability?**
If this report involves a potential vulnerability (e.g. a way to decrypt data without the correct
key, bypass `envelope-access.ts`'s access checks, or forge a break-glass grant), **do not** file it
here — see [SECURITY.md](../../SECURITY.md) for private disclosure instead.
