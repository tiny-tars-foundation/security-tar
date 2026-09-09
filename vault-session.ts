import { decryptVaultV2 } from "./crypto";

/**
 * A vault this session may open on someone else's behalf, and the envelope that opens it. The shape
 * the provider roster and the support console both hand to the host — one drill-in, not two that
 * agree by coincidence.
 */
export interface VaultEntry {
  patientAccountId: string;
  displayName: string;
  email: string | null;
  r2Key: string;
  envelope: { wrappedDEK: string; ephemeralPublicKeyJwk: JsonWebKey };
}

export interface VaultSession {
  /** The current vault's data key, or null when no vault is open. */
  readonly dek: CryptoKey | null;
  /** The current vault's R2 id (slug of its r2_key), or null. */
  readonly r2Id: string | null;
  /**
   * The signed-in owner's account private key, retained for the session so Account settings can
   * re-wrap it when adding a login method. Null in a provider or support session.
   */
  readonly ownerKey: CryptoKey | null;
  /** A provider account's private key, which unwraps each patient's envelope. Null for an owner. */
  readonly providerKey: CryptoKey | null;
  /** True only when a vault is genuinely open — derived, never tracked separately. */
  readonly isOpen: boolean;

  /** Opens a vault: the id and the key that decrypts it, together or not at all. */
  open(r2Id: string, dek: CryptoKey): void;
  /** Retains the owner's account key for this session. */
  setOwnerKey(key: CryptoKey | null): void;
  /** Retains a provider's account key for this session. */
  setProviderKey(key: CryptoKey | null): void;
  /**
   * Closes the open vault. Clears the data key and the id together.
   *
   * Does NOT clear the provider key: a provider who leaves one patient is still signed in and still
   * needs their own key to open the next. That asymmetry was already the behaviour of
   * `backToRoster()`; stating it here is what stops it being re-derived incorrectly later.
   */
  close(): void;
  /** Ends the whole session — every key, including the provider's. */
  signOut(): void;
}

/**
 * Decrypts a vault blob and opens the session on it in one step, shared by every path that unlocks
 * a vault — the signed-in owner's own, and a provider's drill-in to a patient's. `fetchBlob` stays a
 * caller-supplied thunk because fetching it (the R2 route, the ETag it must remember for later saves)
 * is app-local, not frame-generic.
 */
export async function openVault<V>(session: VaultSession, id: string, dek: CryptoKey, fetchBlob: (id: string) => Promise<Uint8Array>): Promise<V> {
  const vault = await decryptVaultV2<V>(await fetchBlob(id), dek);
  session.open(id, dek);
  return vault;
}
