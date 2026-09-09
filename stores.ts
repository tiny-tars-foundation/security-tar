// Storage-agnostic contracts for the identity/vault/access-control data this package's crypto
// operates over. No Cloudflare or D1 dependency here by design (see README.md) — an adopter wires
// these to whatever database they run. `adapters/d1/` in this package is one implementation of
// these contracts, not the definition of them; an adopter's own server code should import the
// types below rather than redeclaring them, so there is exactly one definition of each shape.

export type LifecycleStage = "waitlist" | "lead" | "active" | "paying" | "churned";
export type AuthMethod = "passkey" | "google" | "password" | "recovery";
export type ProviderKind = "clinician" | "support";
export type LinkStatus = "invited" | "active" | "revoked";
export type UnitSystem = "metric" | "imperial";

export interface Account {
  id: string;
  email: string | null;
  emailConfirmed: boolean;
  displayName: string;
  lifecycleStage: LifecycleStage;
  providerKind: ProviderKind | null;
  unitSystem: UnitSystem | null;
  createdAt: string;
  /** Set when the account was erased; every personal field is null from that moment. */
  deletedAt?: string | null;
  /** When the email address was last changed. Null means never. */
  emailChangedAt?: string | null;
}

export interface Identity {
  id: string;
  accountId: string;
  method: AuthMethod;
  providerSubject: string | null;
  credentialId: string | null;
  createdAt: string;
}
export interface Credential {
  accountId: string;
  method: AuthMethod;
  wrappedPrivateKey: Uint8Array;
  kdfParams: unknown;
  createdAt: string;
}
export interface PublicKey {
  accountId: string;
  publicKeyJwk: unknown;
  createdAt: string;
}

export interface VaultRow {
  vaultId: string;
  ownerAccountId: string;
  r2Key: string;
  hd1Version: number;
  /** Set on support-grant expiry; the owner's next login re-keys and clears it. */
  rotationPending: boolean;
  /** Set when the owner revokes the org-recovery envelope. */
  orgRecoveryRevokedAt: string | null;
  /** The object an in-flight re-key is writing to, before the pointer swap. */
  rotationStagingR2Key: string | null;
}
export interface Envelope {
  vaultId: string;
  principalAccountId: string;
  wrappedDek: Uint8Array;
  ephemeralPublicKeyJwk: unknown;
  createdBy: string;
  createdAt: string;
}
export interface EnvelopeInput {
  principalAccountId: string;
  wrappedDek: Uint8Array;
  ephemeralPublicKeyJwk: unknown;
}

export interface ProviderLink {
  id: string;
  patientAccountId: string;
  providerAccountId: string;
  role: ProviderKind;
  status: LinkStatus;
  consentRef: string | null;
  grantedBy: string;
  grantedAt: string;
  /** Set on time-boxed support grants; null for clinician links. */
  expiresAt: string | null;
}

/** A PHI-access audit-log entry — who touched whose vault, and why. */
export interface AccessEvent {
  id: string;
  actorAccountId: string;
  subjectAccountId: string;
  vaultId: string | null;
  action: string;
  consentRef: string | null;
  meta: unknown;
  createdAt: string;
}

export interface AccountStore {
  create(a: {
    id: string;
    displayName: string;
    email?: string | null;
    lifecycleStage?: LifecycleStage;
    providerKind?: ProviderKind | null;
  }): Promise<Account>;
  get(id: string): Promise<Account | null>;
  getByEmail(email: string): Promise<Account | null>;
  sessionsValidFrom(accountId: string): Promise<number | null>;
  revokeSessions(accountId: string): Promise<void>;
  setEmailConfirmed(id: string, confirmed: boolean): Promise<void>;
  setLifecycleStage(id: string, stage: LifecycleStage): Promise<void>;
  updateProfile(id: string, updates: { email?: string | null; displayName?: string; unitSystem?: UnitSystem | null }): Promise<void>;
  tombstone(accountId: string, at: string): Promise<void>;
  markEmailChanged(accountId: string, at: string): Promise<void>;
}

/** Auth-method linkage (`Identity`) plus the key material it points at (`Credential`, `PublicKey`). */
export interface CredentialStore {
  addIdentity(i: { accountId: string; method: AuthMethod; providerSubject?: string | null; credentialId?: string | null; id?: string }): Promise<Identity>;
  getIdentityByProviderSubject(method: AuthMethod, subject: string): Promise<Identity | null>;
  getIdentityByCredentialId(credentialId: string): Promise<Identity | null>;
  listIdentities(accountId: string): Promise<Identity[]>;
  deleteIdentity(accountId: string, method: AuthMethod): Promise<void>;
  putCredential(c: { accountId: string; method: AuthMethod; wrappedPrivateKey: Uint8Array; kdfParams: unknown }): Promise<void>;
  getCredential(accountId: string, method: AuthMethod): Promise<Credential | null>;
  listCredentials(accountId: string): Promise<{ method: AuthMethod; createdAt: string }[]>;
  deleteCredential(accountId: string, method: AuthMethod): Promise<void>;
  updatePasskeyCounter(accountId: string, counter: number): Promise<void>;
  putPublicKey(p: { accountId: string; publicKeyJwk: unknown }): Promise<void>;
  getPublicKey(accountId: string): Promise<PublicKey | null>;
}

/**
 * Vault + envelope storage only — no access policy. `getEnvelopeRow` answers "does a row exist",
 * not "may this principal open the vault"; see `resolveEnvelopeAccess` in ./envelope-access for
 * the policy that composes this with `ProviderLinkStore`.
 */
export interface EnvelopeStore {
  createVault(v: { vaultId: string; ownerAccountId: string; r2Key: string; hd1Version: number }): Promise<VaultRow>;
  getVault(vaultId: string): Promise<VaultRow | null>;
  getVaultByR2Key(r2Key: string): Promise<VaultRow | null>;
  getVaultByStagingR2Key(r2Key: string): Promise<VaultRow | null>;
  listVaultsForOwner(ownerAccountId: string): Promise<VaultRow[]>;
  setRotationPending(vaultId: string, pending: boolean): Promise<void>;
  setRotationStaging(vaultId: string, r2Key: string | null): Promise<void>;
  setOrgRecoveryRevoked(vaultId: string, at: string | null): Promise<void>;
  putEnvelope(e: { vaultId: string; principalAccountId: string; wrappedDek: Uint8Array; ephemeralPublicKeyJwk: unknown; createdBy: string }): Promise<void>;
  /** Atomically swaps a vault's whole envelope set. */
  replaceEnvelopes(vaultId: string, envelopes: EnvelopeInput[], createdBy: string): Promise<void>;
  /** Atomically swaps the envelope set AND repoints the vault at a freshly-written object. */
  commitRotation(vaultId: string, newR2Key: string, envelopes: EnvelopeInput[], createdBy: string): Promise<void>;
  getEnvelopeRow(vaultId: string, principalAccountId: string): Promise<Envelope | null>;
  listEnvelopesForVault(vaultId: string): Promise<Envelope[]>;
  listEnvelopesForPrincipal(principalAccountId: string): Promise<Envelope[]>;
  deleteEnvelope(vaultId: string, principalAccountId: string): Promise<void>;
}

export interface ProviderLinkStore {
  create(l: {
    patientAccountId: string;
    providerAccountId: string;
    role: ProviderKind;
    status?: LinkStatus;
    consentRef?: string | null;
    grantedBy: string;
    expiresAt?: string | null;
    id?: string;
  }): Promise<ProviderLink>;
  updateStatus(id: string, status: LinkStatus): Promise<void>;
  grantSupport(id: string, opts: { expiresAt: string | null; consentRef?: string | null }): Promise<void>;
  get(id: string): Promise<ProviderLink | null>;
  listForPatient(patientAccountId: string): Promise<ProviderLink[]>;
  listForProvider(providerAccountId: string): Promise<ProviderLink[]>;
  /** The active, unexpired link between this patient and provider, or null. */
  getActive(patientAccountId: string, providerAccountId: string): Promise<ProviderLink | null>;
}

/**
 * The PHI-access half of an adopter's audit trail only. Lifecycle/CRM events and raw-object
 * ownership bookkeeping are app-specific concerns that don't belong in a portable security package.
 */
export interface AuditStore {
  insertAccessEvent(e: { actorAccountId: string; subjectAccountId: string; vaultId?: string | null; action: string; consentRef?: string | null; meta?: unknown; id?: string }): Promise<AccessEvent>;
  listAccessEventsForSubject(subjectAccountId: string): Promise<AccessEvent[]>;
}
