// The time-boxed "support agent gets temporary access, then it lapses or is pulled" pattern, factored
// out of routes that would otherwise each hardcode their own TTL clamp, consent-string prefix, and
// audit shape: a grant-with-envelope route, a grant-metadata-only route, a check/expire route, and a
// revoke route. Parameterized TTL rather than a fixed default, so an adopter with different
// access-window needs isn't stuck with ours.

import type { AuditStore, EnvelopeStore, ProviderLink, ProviderLinkStore } from "./stores";

export interface BreakGlassPolicy {
  defaultTtlHours: number;
  maxTtlHours: number;
}

function clampTtlHours(requested: number | undefined, policy: BreakGlassPolicy): number {
  return typeof requested === "number" && requested > 0 ? Math.min(requested, policy.maxTtlHours) : policy.defaultTtlHours;
}

export type BreakGlassGrantResult = { ok: true; expiresAt: string } | { ok: false; error: "no_pending_link" };

export interface BreakGlassGrantStores {
  links: Pick<ProviderLinkStore, "get" | "grantSupport">;
  audit: Pick<AuditStore, "insertAccessEvent">;
  /** Only required when a grant call passes `envelope`. */
  envelopes?: Pick<EnvelopeStore, "putEnvelope">;
}

/**
 * Approves a pending support-role link: validates it's the approver's own pending request, clamps the
 * requested TTL, stamps a consent ref, optionally writes an envelope (patient approvals only — a
 * provider approving a roster request owns nothing encrypted), flips the link active, and audits.
 */
export async function grantBreakGlass(
  stores: BreakGlassGrantStores,
  opts: {
    linkId: string;
    approverAccountId: string;
    requestedTtlHours: number | undefined;
    policy: BreakGlassPolicy;
    consentPrefix: string;
    auditAction: string;
    envelope?: { vaultId: string; wrappedDek: Uint8Array; ephemeralPublicKeyJwk: unknown };
    buildAuditMeta: (expiresAt: string, link: ProviderLink) => unknown;
  }
): Promise<BreakGlassGrantResult> {
  const link = await stores.links.get(opts.linkId);
  if (!link || link.patientAccountId !== opts.approverAccountId || link.role !== "support" || link.status !== "invited") {
    return { ok: false, error: "no_pending_link" };
  }

  const ttlHours = clampTtlHours(opts.requestedTtlHours, opts.policy);
  const expiresAt = new Date(Date.now() + ttlHours * 3600 * 1000).toISOString();
  const consentRef = `${opts.consentPrefix}:${new Date().toISOString()}`;

  if (opts.envelope) {
    if (!stores.envelopes) throw new Error("grantBreakGlass: envelope requested but no envelope store supplied");
    await stores.envelopes.putEnvelope({
      vaultId: opts.envelope.vaultId,
      principalAccountId: link.providerAccountId,
      wrappedDek: opts.envelope.wrappedDek,
      ephemeralPublicKeyJwk: opts.envelope.ephemeralPublicKeyJwk,
      createdBy: opts.approverAccountId,
    });
  }
  await stores.links.grantSupport(link.id, { expiresAt, consentRef });
  await stores.audit.insertAccessEvent({
    actorAccountId: opts.approverAccountId,
    subjectAccountId: opts.approverAccountId,
    vaultId: opts.envelope?.vaultId ?? null,
    action: opts.auditAction,
    consentRef,
    meta: opts.buildAuditMeta(expiresAt, link),
  });

  return { ok: true, expiresAt };
}

export type BreakGlassCheckResult = { ok: true } | { ok: false; error: "expired" };

export interface BreakGlassCheckStores {
  links: Pick<ProviderLinkStore, "updateStatus">;
  audit: Pick<AuditStore, "insertAccessEvent">;
}

/**
 * Checks whether an active support-role link has passed its TTL. Past expiry, self-revokes the link
 * and audits `expiredAuditAction`; `onExpire` is the caller's chance to clean up whatever the grant
 * attached (an envelope, for the vault-access case — nothing, for a metadata-only grant).
 */
export async function checkBreakGlass(
  stores: BreakGlassCheckStores,
  opts: {
    link: ProviderLink;
    actorAccountId: string;
    subjectAccountId: string;
    vaultId: string | null;
    now?: number;
    expiredAuditAction: string;
    onExpire?: () => Promise<void>;
  }
): Promise<BreakGlassCheckResult> {
  const now = opts.now ?? Date.now();
  if (!opts.link.expiresAt || new Date(opts.link.expiresAt).getTime() >= now) {
    return { ok: true };
  }

  if (opts.onExpire) await opts.onExpire();
  await stores.links.updateStatus(opts.link.id, "revoked");
  await stores.audit.insertAccessEvent({
    actorAccountId: opts.actorAccountId,
    subjectAccountId: opts.subjectAccountId,
    vaultId: opts.vaultId,
    action: opts.expiredAuditAction,
    consentRef: opts.link.consentRef,
  });

  return { ok: false, error: "expired" };
}

export interface BreakGlassRevokeStores {
  links: Pick<ProviderLinkStore, "updateStatus">;
  audit: Pick<AuditStore, "insertAccessEvent">;
  /** Only required when the link being revoked has a vault (i.e. is not metadata-only). */
  envelopes?: Pick<EnvelopeStore, "deleteEnvelope">;
}

/**
 * Ends a link early — either side may call this (the patient revoking, or the provider dropping it).
 * Deletes the provider's envelope (if any) so no new read can unwrap the DEK, and marks the link
 * revoked. Idempotent: a second call re-deletes (no-op) and re-marks revoked (no-op); `auditAction` is
 * omitted for link kinds that don't carry a disclosure-audit obligation (clinician links).
 */
export async function revokeBreakGlass(
  stores: BreakGlassRevokeStores,
  opts: {
    linkId: string;
    actorAccountId: string;
    subjectAccountId: string;
    providerAccountId: string;
    vaultId: string | null;
    auditAction?: string;
    auditMeta?: unknown;
  }
): Promise<void> {
  if (opts.vaultId) {
    if (!stores.envelopes) throw new Error("revokeBreakGlass: vaultId given but no envelope store supplied");
    await stores.envelopes.deleteEnvelope(opts.vaultId, opts.providerAccountId);
  }
  await stores.links.updateStatus(opts.linkId, "revoked");
  if (opts.auditAction) {
    await stores.audit.insertAccessEvent({
      actorAccountId: opts.actorAccountId,
      subjectAccountId: opts.subjectAccountId,
      vaultId: opts.vaultId,
      action: opts.auditAction,
      meta: opts.auditMeta,
    });
  }
}
