import { wrapDEKForPublicKey } from "./crypto";
import { bytesToBase64, failed } from "./auth-client";

// Support consented-access. A vault owner approves a pending support request by wrapping their
// in-memory DEK to the support agent's public key (time-boxed); support enters via an audited endpoint.

// Owner side — approve a pending support request (linkId + the agent's publicKeyJwk from GET /api/providers).
export async function approveSupport(linkId: string, dek: CryptoKey, publicKeyJwk: JsonWebKey, ttlHours: number): Promise<void> {
  const env = await wrapDEKForPublicKey(dek, publicKeyJwk);
  const res = await fetch("/api/support/approve", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ linkId, wrappedDEK: bytesToBase64(env.wrappedDEK), ephemeralPublicKeyJwk: env.ephemeralPublicKeyJwk, ttlHours }),
  });
  if (!res.ok) throw await failed(res, "approve failed");
}

// Support side.
export interface SupportOwner {
  ownerAccountId: string;
  displayName: string;
  expiresAt: string | null;
}

export async function requestSupportAccess(ownerEmail: string): Promise<void> {
  const res = await fetch("/api/support/request", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ownerEmail }),
  });
  if (!res.ok) throw await failed(res, "request failed");
}

export async function listSupportOwners(): Promise<SupportOwner[]> {
  const res = await fetch("/api/support/owners", { cache: "no-store" });
  if (!res.ok) throw await failed(res, "support owners failed");
  return ((await res.json()) as { owners: SupportOwner[] }).owners;
}

// Enter an owner's vault (audited server-side); returns the envelope for client-side DEK unwrap.
export async function enterSupportOwner(ownerAccountId: string): Promise<{
  ownerAccountId: string;
  displayName: string;
  email: string | null;
  vaultId: string;
  r2Key: string;
  envelope: { wrappedDEK: string; ephemeralPublicKeyJwk: JsonWebKey };
}> {
  const res = await fetch("/api/support/access", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ownerAccountId }),
  });
  if (!res.ok) throw await failed(res, "support access failed");
  return res.json();
}

// Support→provider roster access. A support agent can request access to a primary provider too (same
// /api/support/request, which classifies by the target's kind). The primary provider approves (metadata
// only, no DEK), then support sees their roster and can open the owners who separately consented.

export interface SupportProvider {
  linkId: string;
  providerAccountId: string;
  displayName: string;
  email: string | null;
  expiresAt: string | null;
}

export interface SupportRosterOwner {
  ownerAccountId: string;
  displayName: string;
  email: string | null;
  openable: boolean;
  pending: boolean;
}

export interface SupportRequest {
  linkId: string;
  targetAccountId: string;
  displayName: string;
  email: string | null;
  kind: "owner" | "provider";
}

// Provider side — approve a pending support roster request (no DEK; a provider owns no vault).
export async function approveSupportAsProvider(linkId: string, ttlHours: number): Promise<void> {
  const res = await fetch("/api/providers/approve-support", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ linkId, ttlHours }),
  });
  if (!res.ok) throw await failed(res, "approve failed");
}

export async function listSupportProviders(): Promise<SupportProvider[]> {
  const res = await fetch("/api/support/providers", { cache: "no-store" });
  if (!res.ok) throw await failed(res, "support providers failed");
  return ((await res.json()) as { providers: SupportProvider[] }).providers;
}

export async function getProviderRoster(providerId: string): Promise<SupportRosterOwner[]> {
  const res = await fetch(`/api/support/provider-roster?providerId=${encodeURIComponent(providerId)}`, { cache: "no-store" });
  if (!res.ok) throw await failed(res, "provider roster failed");
  return ((await res.json()) as { roster: SupportRosterOwner[] }).roster;
}

export async function listSupportRequests(): Promise<SupportRequest[]> {
  const res = await fetch("/api/support/requests", { cache: "no-store" });
  if (!res.ok) throw await failed(res, "support requests failed");
  return ((await res.json()) as { requests: SupportRequest[] }).requests;
}

// Cancel a pending request the support agent made (support is the provider side of the link).
export async function cancelSupportRequest(linkId: string): Promise<void> {
  const res = await fetch(`/api/providers/${encodeURIComponent(linkId)}`, { method: "DELETE" });
  if (!res.ok) throw await failed(res, "cancel failed");
}
