import type { Envelope, ProviderLink, VaultRow } from "./stores";

// Narrow, structural slices of EnvelopeStore/ProviderLinkStore — only what the policy below reads.
// Any conforming store satisfies these without change; an adopter with no "org recovery account"
// concept can call this with orgAccountId set to a value nothing will ever match, or skip it.
export interface EnvelopeAccessSource {
  getEnvelopeRow(vaultId: string, principalAccountId: string): Promise<Envelope | null>;
  getVault(vaultId: string): Promise<VaultRow | null>;
}
export interface ProviderLinkSource {
  getActive(ownerAccountId: string, providerAccountId: string): Promise<ProviderLink | null>;
}

/**
 * The envelope a principal may actually use, or null.
 *
 * This check has to live here, composed once, rather than duplicated per route — that is exactly
 * how it was bypassed before: expiry was enforced lazily and only inside individual routes, so a
 * grantee who never called the one endpoint that self-revokes a lapsed grant could keep reading PHI
 * indefinitely. The grant's own expiry was real; nothing on the read path consulted it.
 *
 * The owner needs no link (they have no provider-link row about themselves), and neither does the
 * org-recovery principal, whose envelope the owner can revoke outright — recorded on the vault, not
 * as a link.
 */
export async function resolveEnvelopeAccess(
  envelopes: EnvelopeAccessSource,
  providers: ProviderLinkSource,
  vaultId: string,
  principalAccountId: string,
  orgAccountId: string
): Promise<Envelope | null> {
  const envelope = await envelopes.getEnvelopeRow(vaultId, principalAccountId);
  if (!envelope) return null;

  const vault = await envelopes.getVault(vaultId);
  if (!vault) return null;
  if (vault.ownerAccountId === principalAccountId) return envelope;
  if (principalAccountId === orgAccountId) return vault.orgRecoveryRevokedAt ? null : envelope;

  const link = await providers.getActive(vault.ownerAccountId, principalAccountId);
  if (!link) return null;
  return envelope;
}
