import { describe, it, expect } from "vitest";
import { resolveEnvelopeAccess } from "../envelope-access";
import type { EnvelopeAccessSource, ProviderLinkSource } from "../envelope-access";
import type { Envelope, ProviderLink, VaultRow } from "../stores";

const ORG_ACCOUNT_ID = "org-recovery";

function makeEnvelope(vaultId: string, principalAccountId: string): Envelope {
  return {
    vaultId,
    principalAccountId,
    wrappedDek: new Uint8Array([1]),
    ephemeralPublicKeyJwk: {},
    createdBy: principalAccountId,
    createdAt: "2026-01-01T00:00:00.000Z",
  };
}

function makeVault(overrides: Partial<VaultRow> = {}): VaultRow {
  return {
    vaultId: "vault-1",
    ownerAccountId: "owner",
    r2Key: "r2/vault-1",
    hd1Version: 2,
    rotationPending: false,
    orgRecoveryRevokedAt: null,
    rotationStagingR2Key: null,
    ...overrides,
  };
}

function makeStores(vault: VaultRow | null, envelopes: Envelope[], links: ProviderLink[]) {
  const envelopeSource: EnvelopeAccessSource = {
    async getEnvelopeRow(vaultId, principalAccountId) {
      return envelopes.find((e) => e.vaultId === vaultId && e.principalAccountId === principalAccountId) ?? null;
    },
    async getVault(vaultId) {
      return vault && vault.vaultId === vaultId ? vault : null;
    },
  };
  const providerLinkSource: ProviderLinkSource = {
    async getActive(ownerAccountId, providerAccountId) {
      return (
        links.find(
          (l) =>
            l.ownerAccountId === ownerAccountId &&
            l.providerAccountId === providerAccountId &&
            l.status === "active",
        ) ?? null
      );
    },
  };
  return { envelopeSource, providerLinkSource };
}

function makeLink(overrides: Partial<ProviderLink> = {}): ProviderLink {
  return {
    id: "link-1",
    ownerAccountId: "owner",
    providerAccountId: "provider",
    role: "primary",
    status: "active",
    consentRef: null,
    grantedBy: "owner",
    grantedAt: "2026-01-01T00:00:00.000Z",
    expiresAt: null,
    ...overrides,
  };
}

describe("resolveEnvelopeAccess", () => {
  it("returns null when the principal has no envelope row at all", async () => {
    const vault = makeVault();
    const { envelopeSource, providerLinkSource } = makeStores(vault, [], []);
    const result = await resolveEnvelopeAccess(envelopeSource, providerLinkSource, vault.vaultId, "stranger", ORG_ACCOUNT_ID);
    expect(result).toBeNull();
  });

  it("returns null when the vault row itself is missing (orphaned envelope)", async () => {
    const { envelopeSource, providerLinkSource } = makeStores(null, [makeEnvelope("vault-1", "owner")], []);
    const result = await resolveEnvelopeAccess(envelopeSource, providerLinkSource, "vault-1", "owner", ORG_ACCOUNT_ID);
    expect(result).toBeNull();
  });

  it("the owner always gets their envelope back, with no provider link needed", async () => {
    const vault = makeVault();
    const envelope = makeEnvelope(vault.vaultId, "owner");
    const { envelopeSource, providerLinkSource } = makeStores(vault, [envelope], []);
    const result = await resolveEnvelopeAccess(envelopeSource, providerLinkSource, vault.vaultId, "owner", ORG_ACCOUNT_ID);
    expect(result).toBe(envelope);
  });

  it("the org-recovery principal gets their envelope when recovery has not been revoked", async () => {
    const vault = makeVault({ orgRecoveryRevokedAt: null });
    const envelope = makeEnvelope(vault.vaultId, ORG_ACCOUNT_ID);
    const { envelopeSource, providerLinkSource } = makeStores(vault, [envelope], []);
    const result = await resolveEnvelopeAccess(envelopeSource, providerLinkSource, vault.vaultId, ORG_ACCOUNT_ID, ORG_ACCOUNT_ID);
    expect(result).toBe(envelope);
  });

  it("the org-recovery principal is refused once the owner revokes recovery", async () => {
    const vault = makeVault({ orgRecoveryRevokedAt: "2026-02-01T00:00:00.000Z" });
    const envelope = makeEnvelope(vault.vaultId, ORG_ACCOUNT_ID);
    const { envelopeSource, providerLinkSource } = makeStores(vault, [envelope], []);
    const result = await resolveEnvelopeAccess(envelopeSource, providerLinkSource, vault.vaultId, ORG_ACCOUNT_ID, ORG_ACCOUNT_ID);
    expect(result).toBeNull();
  });

  it("a provider with an active link and an envelope gets it back", async () => {
    const vault = makeVault();
    const envelope = makeEnvelope(vault.vaultId, "provider");
    const link = makeLink();
    const { envelopeSource, providerLinkSource } = makeStores(vault, [envelope], [link]);
    const result = await resolveEnvelopeAccess(envelopeSource, providerLinkSource, vault.vaultId, "provider", ORG_ACCOUNT_ID);
    expect(result).toBe(envelope);
  });

  it("a provider whose link is revoked is refused even with an envelope row still present", async () => {
    // This is the bug class the function exists to close: a stale/revoked link must not be
    // treated as active just because an envelope was never cleaned up.
    const vault = makeVault();
    const envelope = makeEnvelope(vault.vaultId, "provider");
    const link = makeLink({ status: "revoked" });
    const { envelopeSource, providerLinkSource } = makeStores(vault, [envelope], [link]);
    const result = await resolveEnvelopeAccess(envelopeSource, providerLinkSource, vault.vaultId, "provider", ORG_ACCOUNT_ID);
    expect(result).toBeNull();
  });

  it("a principal with an envelope but no link at all is refused", async () => {
    const vault = makeVault();
    const envelope = makeEnvelope(vault.vaultId, "provider");
    const { envelopeSource, providerLinkSource } = makeStores(vault, [envelope], []);
    const result = await resolveEnvelopeAccess(envelopeSource, providerLinkSource, vault.vaultId, "provider", ORG_ACCOUNT_ID);
    expect(result).toBeNull();
  });

  it("an adopter with no org-recovery concept can pass a value nothing will ever match", async () => {
    const vault = makeVault();
    const envelope = makeEnvelope(vault.vaultId, "owner");
    const { envelopeSource, providerLinkSource } = makeStores(vault, [envelope], []);
    const result = await resolveEnvelopeAccess(envelopeSource, providerLinkSource, vault.vaultId, "owner", "__none__");
    expect(result).toBe(envelope);
  });
});
