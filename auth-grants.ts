import { wrapDEKForPublicKey } from "./crypto";
import { bytesToBase64, failed } from "./auth-client";

// Provider escrow (patient side). A logged-in patient grants a provider access by wrapping
// their in-memory DEK to the provider's public key client-side and posting the opaque envelope; the
// server never sees a plaintext DEK. Revoke deletes the envelope + marks the link revoked.

export interface ProviderLinkView {
  linkId: string;
  providerAccountId: string;
  displayName: string;
  kind: "clinician" | "support";
  status: "invited" | "active" | "revoked";
  expiresAt: string | null;
  publicKeyJwk?: JsonWebKey | null; // present only for a pending (invited) support request
}

export async function listMyProviders(): Promise<ProviderLinkView[]> {
  const res = await fetch("/api/providers", { cache: "no-store" });
  if (!res.ok) throw await failed(res, "list providers failed");
  return ((await res.json()) as { providers: ProviderLinkView[] }).providers;
}

// Resolve a provider by email to their public key; null if no such provider (uniform 404).
export async function lookupProvider(
  email: string
): Promise<{ providerAccountId: string; displayName: string; providerKind: string; publicKeyJwk: JsonWebKey } | null> {
  const res = await fetch(`/api/providers/lookup?email=${encodeURIComponent(email)}`);
  if (res.status === 404) return null;
  if (!res.ok) throw await failed(res, "lookup failed");
  return res.json();
}

// Grant a looked-up provider access to the caller's vault. `dek` is the owner's in-memory DEK.
export async function grantProvider(
  dek: CryptoKey,
  provider: { providerAccountId: string; publicKeyJwk: JsonWebKey }
): Promise<void> {
  const env = await wrapDEKForPublicKey(dek, provider.publicKeyJwk);
  const res = await fetch("/api/providers/grant", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      providerAccountId: provider.providerAccountId,
      wrappedDEK: bytesToBase64(env.wrappedDEK),
      ephemeralPublicKeyJwk: env.ephemeralPublicKeyJwk,
    }),
  });
  if (!res.ok) throw await failed(res, "grant failed");
}

export async function revokeProvider(linkId: string): Promise<void> {
  const res = await fetch(`/api/providers/${encodeURIComponent(linkId)}`, { method: "DELETE" });
  if (!res.ok) throw await failed(res, "revoke failed");
}
