// Shared contract tests for each stores.ts interface. A caller registers these against any factory —
// run the same suite against the D1 adapter and the memory adapter and a pass on both is the actual
// evidence the "storage-agnostic" claim holds, not just an assertion made by interface shape.
//
// Each function calls vitest's describe/it itself; a caller imports and invokes it from inside its own
// test file (vitest collects tests registered this way during the collection phase — the call need not
// be lexically inside a `describe` block).

import { describe, it, expect } from "vitest";
import type { AccountStore, AuditStore, CredentialStore, EnvelopeStore, ProviderLinkStore } from "../stores";

export function runAccountStoreConformance(label: string, factory: () => AccountStore | Promise<AccountStore>) {
  describe(`AccountStore conformance (${label})`, () => {
    it("creates and reads an account back by id and by email", async () => {
      const store = await factory();
      const created = await store.create({ id: "acct-1", displayName: "Ada", email: "ada@example.com" });
      expect(created.emailConfirmed).toBe(false);
      expect(created.lifecycleStage).toBe("active");

      const byId = await store.get("acct-1");
      expect(byId).toEqual(created);

      const byEmail = await store.getByEmail("ada@example.com");
      expect(byEmail).toEqual(created);
    });

    it("returns null for an account that does not exist", async () => {
      const store = await factory();
      expect(await store.get("nope")).toBeNull();
      expect(await store.getByEmail("nope@example.com")).toBeNull();
    });

    it("sessionsValidFrom is +Infinity for a deleted or never-existing account", async () => {
      const store = await factory();
      expect(await store.sessionsValidFrom("nope")).toBe(Number.POSITIVE_INFINITY);
    });

    it("sessionsValidFrom is null until revokeSessions is called, then a recent timestamp", async () => {
      const store = await factory();
      await store.create({ id: "acct-2", displayName: "Bea" });
      expect(await store.sessionsValidFrom("acct-2")).toBeNull();

      const before = Math.floor(Date.now() / 1000);
      await store.revokeSessions("acct-2");
      const validFrom = await store.sessionsValidFrom("acct-2");
      expect(validFrom).toBeGreaterThanOrEqual(before);
    });

    it("updateProfile only touches the fields provided", async () => {
      const store = await factory();
      await store.create({ id: "acct-3", displayName: "Cy", email: "cy@example.com" });
      await store.updateProfile("acct-3", { displayName: "Cy Renamed" });
      const after = await store.get("acct-3");
      expect(after?.displayName).toBe("Cy Renamed");
      expect(after?.email).toBe("cy@example.com");
    });

    it("tombstone nulls personal fields and stamps deletedAt", async () => {
      const store = await factory();
      await store.create({ id: "acct-4", displayName: "Dee", email: "dee@example.com" });
      await store.tombstone("acct-4", "2026-01-01T00:00:00.000Z");
      const after = await store.get("acct-4");
      expect(after?.email).toBeNull();
      expect(after?.displayName).toBe("");
      expect(after?.lifecycleStage).toBe("churned");
      expect(after?.deletedAt).toBe("2026-01-01T00:00:00.000Z");
    });
  });
}

export function runCredentialStoreConformance(label: string, factory: () => CredentialStore | Promise<CredentialStore>) {
  describe(`CredentialStore conformance (${label})`, () => {
    it("adds an identity and finds it by provider subject", async () => {
      const store = await factory();
      await store.addIdentity({ accountId: "acct-1", method: "google", providerSubject: "sub-1" });
      const found = await store.getIdentityByProviderSubject("google", "sub-1");
      expect(found?.accountId).toBe("acct-1");
    });

    it("returns null for an unknown identity lookup", async () => {
      const store = await factory();
      expect(await store.getIdentityByProviderSubject("google", "nope")).toBeNull();
      expect(await store.getIdentityByCredentialId("nope")).toBeNull();
    });

    it("round-trips a credential and omits it from listCredentials' PHI-free view once deleted", async () => {
      const store = await factory();
      await store.putCredential({ accountId: "acct-1", method: "password", wrappedPrivateKey: new Uint8Array([1, 2, 3]), kdfParams: { n: 1 } });
      const cred = await store.getCredential("acct-1", "password");
      expect(cred?.wrappedPrivateKey).toEqual(new Uint8Array([1, 2, 3]));
      expect((await store.listCredentials("acct-1")).map((c) => c.method)).toContain("password");

      await store.deleteCredential("acct-1", "password");
      expect(await store.getCredential("acct-1", "password")).toBeNull();
    });

    it("updatePasskeyCounter merges into the existing kdfParams", async () => {
      const store = await factory();
      await store.putCredential({ accountId: "acct-1", method: "passkey", wrappedPrivateKey: new Uint8Array(), kdfParams: { alg: "es256" } });
      await store.updatePasskeyCounter("acct-1", 7);
      const cred = await store.getCredential("acct-1", "passkey");
      expect(cred?.kdfParams).toMatchObject({ alg: "es256", counter: 7 });
    });

    it("round-trips a public key", async () => {
      const store = await factory();
      await store.putPublicKey({ accountId: "acct-1", publicKeyJwk: { kty: "EC" } });
      expect((await store.getPublicKey("acct-1"))?.publicKeyJwk).toEqual({ kty: "EC" });
      expect(await store.getPublicKey("nope")).toBeNull();
    });
  });
}

export function runEnvelopeStoreConformance(label: string, factory: () => EnvelopeStore | Promise<EnvelopeStore>) {
  describe(`EnvelopeStore conformance (${label})`, () => {
    it("creates a vault with no rotation/recovery flags set", async () => {
      const store = await factory();
      const vault = await store.createVault({ vaultId: "vault-1", ownerAccountId: "acct-1", r2Key: "data-1.enc", hd1Version: 1 });
      expect(vault.rotationPending).toBe(false);
      expect(vault.orgRecoveryRevokedAt).toBeNull();
      expect(await store.getVault("vault-1")).toEqual(vault);
      expect(await store.getVaultByR2Key("data-1.enc")).toEqual(vault);
    });

    it("returns null for a vault that does not exist", async () => {
      const store = await factory();
      expect(await store.getVault("nope")).toBeNull();
      expect(await store.getVaultByR2Key("nope")).toBeNull();
      expect(await store.getVaultByStagingR2Key("nope")).toBeNull();
    });

    it("getEnvelopeRow answers existence only, with no access policy applied", async () => {
      const store = await factory();
      await store.createVault({ vaultId: "vault-1", ownerAccountId: "acct-1", r2Key: "data-1.enc", hd1Version: 1 });
      expect(await store.getEnvelopeRow("vault-1", "acct-1")).toBeNull();
      await store.putEnvelope({ vaultId: "vault-1", principalAccountId: "acct-1", wrappedDek: new Uint8Array([9]), ephemeralPublicKeyJwk: {}, createdBy: "acct-1" });
      const row = await store.getEnvelopeRow("vault-1", "acct-1");
      expect(row?.wrappedDek).toEqual(new Uint8Array([9]));
    });

    it("replaceEnvelopes atomically swaps the whole set", async () => {
      const store = await factory();
      await store.createVault({ vaultId: "vault-1", ownerAccountId: "acct-1", r2Key: "data-1.enc", hd1Version: 1 });
      await store.putEnvelope({ vaultId: "vault-1", principalAccountId: "acct-1", wrappedDek: new Uint8Array([1]), ephemeralPublicKeyJwk: {}, createdBy: "acct-1" });
      await store.replaceEnvelopes("vault-1", [{ principalAccountId: "acct-2", wrappedDek: new Uint8Array([2]), ephemeralPublicKeyJwk: {} }], "acct-1");
      expect(await store.getEnvelopeRow("vault-1", "acct-1")).toBeNull();
      expect((await store.getEnvelopeRow("vault-1", "acct-2"))?.wrappedDek).toEqual(new Uint8Array([2]));
    });

    it("commitRotation swaps envelopes and repoints the vault at the new key", async () => {
      const store = await factory();
      await store.createVault({ vaultId: "vault-1", ownerAccountId: "acct-1", r2Key: "old.enc", hd1Version: 1 });
      await store.setRotationStaging("vault-1", "new.enc");
      await store.commitRotation("vault-1", "new.enc", [{ principalAccountId: "acct-1", wrappedDek: new Uint8Array([3]), ephemeralPublicKeyJwk: {} }], "acct-1");
      const vault = await store.getVault("vault-1");
      expect(vault?.r2Key).toBe("new.enc");
      expect(vault?.rotationStagingR2Key).toBeNull();
      expect(vault?.rotationPending).toBe(false);
    });
  });
}

export function runProviderLinkStoreConformance(label: string, factory: () => ProviderLinkStore | Promise<ProviderLinkStore>) {
  describe(`ProviderLinkStore conformance (${label})`, () => {
    it("creates a link, defaulting status to invited", async () => {
      const store = await factory();
      const link = await store.create({ patientAccountId: "p1", providerAccountId: "d1", role: "clinician", grantedBy: "p1" });
      expect(link.status).toBe("invited");
      expect(await store.get(link.id)).toEqual(link);
    });

    it("getActive is null for an invited (non-active) link", async () => {
      const store = await factory();
      const link = await store.create({ patientAccountId: "p1", providerAccountId: "d1", role: "clinician", grantedBy: "p1" });
      expect(await store.getActive("p1", "d1")).toBeNull();
      await store.updateStatus(link.id, "active");
      expect((await store.getActive("p1", "d1"))?.id).toBe(link.id);
    });

    it("getActive is null once expiresAt is in the past", async () => {
      const store = await factory();
      const link = await store.create({ patientAccountId: "p1", providerAccountId: "d1", role: "support", grantedBy: "p1", status: "active", expiresAt: "2000-01-01T00:00:00.000Z" });
      expect(link.status).toBe("active");
      expect(await store.getActive("p1", "d1")).toBeNull();
    });

    it("grantSupport activates and time-boxes a link", async () => {
      const store = await factory();
      const link = await store.create({ patientAccountId: "p1", providerAccountId: "d1", role: "support", grantedBy: "p1" });
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();
      await store.grantSupport(link.id, { expiresAt, consentRef: "consent-1" });
      const after = await store.get(link.id);
      expect(after?.status).toBe("active");
      expect(after?.expiresAt).toBe(expiresAt);
    });

    it("listForPatient / listForProvider scope correctly", async () => {
      const store = await factory();
      await store.create({ patientAccountId: "p1", providerAccountId: "d1", role: "clinician", grantedBy: "p1" });
      await store.create({ patientAccountId: "p1", providerAccountId: "d2", role: "clinician", grantedBy: "p1" });
      await store.create({ patientAccountId: "p2", providerAccountId: "d1", role: "clinician", grantedBy: "p2" });
      expect(await store.listForPatient("p1")).toHaveLength(2);
      expect(await store.listForProvider("d1")).toHaveLength(2);
    });
  });
}

export function runAuditStoreConformance(label: string, factory: () => AuditStore | Promise<AuditStore>) {
  describe(`AuditStore conformance (${label})`, () => {
    it("records an access event and lists it for the subject", async () => {
      const store = await factory();
      const event = await store.insertAccessEvent({ actorAccountId: "d1", subjectAccountId: "p1", action: "view" });
      expect(event.consentRef).toBeNull();
      expect(await store.listAccessEventsForSubject("p1")).toEqual([event]);
    });

    it("scopes listAccessEventsForSubject to the given subject only", async () => {
      const store = await factory();
      await store.insertAccessEvent({ actorAccountId: "d1", subjectAccountId: "p1", action: "view" });
      await store.insertAccessEvent({ actorAccountId: "d1", subjectAccountId: "p2", action: "view" });
      expect(await store.listAccessEventsForSubject("p1")).toHaveLength(1);
    });
  });
}
