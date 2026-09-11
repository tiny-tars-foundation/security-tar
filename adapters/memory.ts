// In-memory implementations of every stores.ts interface. This is the portability proof: the same
// conformance suite (./conformance.ts) runs unchanged against these and against the D1 adapter, so
// "storage-agnostic" is demonstrated rather than merely asserted by interface shape.

import type {
  Account,
  AccountStore,
  AuditStore,
  AccessEvent,
  AuthMethod,
  Credential,
  CredentialStore,
  Envelope,
  EnvelopeInput,
  EnvelopeStore,
  Identity,
  LifecycleStage,
  LinkStatus,
  ProviderKind,
  ProviderLink,
  ProviderLinkStore,
  PublicKey,
  UnitSystem,
  VaultRow,
} from "../stores";

export class MemoryAccountStore implements AccountStore {
  private byId = new Map<string, Account>();
  private sessionsValidFromMs = new Map<string, number>();

  async create(a: { id: string; displayName: string; email?: string | null; lifecycleStage?: LifecycleStage; providerKind?: ProviderKind | null }): Promise<Account> {
    const account: Account = {
      id: a.id,
      email: a.email ?? null,
      emailConfirmed: false,
      displayName: a.displayName,
      lifecycleStage: a.lifecycleStage ?? "active",
      providerKind: a.providerKind ?? null,
      unitSystem: null,
      createdAt: new Date().toISOString(),
      deletedAt: null,
      emailChangedAt: null,
    };
    this.byId.set(a.id, account);
    return { ...account };
  }

  async get(id: string): Promise<Account | null> {
    const a = this.byId.get(id);
    return a ? { ...a } : null;
  }

  async getByEmail(email: string): Promise<Account | null> {
    for (const a of this.byId.values()) if (a.email === email) return { ...a };
    return null;
  }

  async sessionsValidFrom(accountId: string): Promise<number | null> {
    if (!this.byId.has(accountId)) return Number.POSITIVE_INFINITY;
    return this.sessionsValidFromMs.get(accountId) ?? null;
  }

  async revokeSessions(accountId: string): Promise<void> {
    this.sessionsValidFromMs.set(accountId, Math.floor(Date.now() / 1000));
  }

  async setEmailConfirmed(id: string, confirmed: boolean): Promise<void> {
    const a = this.byId.get(id);
    if (a) a.emailConfirmed = confirmed;
  }

  async setLifecycleStage(id: string, stage: LifecycleStage): Promise<void> {
    const a = this.byId.get(id);
    if (a) a.lifecycleStage = stage;
  }

  async updateProfile(id: string, updates: { email?: string | null; displayName?: string; unitSystem?: UnitSystem | null }): Promise<void> {
    const a = this.byId.get(id);
    if (!a) return;
    if (updates.email !== undefined) a.email = updates.email;
    if (updates.displayName !== undefined) a.displayName = updates.displayName;
    if (updates.unitSystem !== undefined) a.unitSystem = updates.unitSystem;
  }

  async tombstone(accountId: string, at: string): Promise<void> {
    const a = this.byId.get(accountId);
    if (!a) return;
    a.email = null;
    a.emailConfirmed = false;
    a.displayName = "";
    a.lifecycleStage = "churned";
    a.providerKind = null;
    a.unitSystem = null;
    a.deletedAt = at;
  }

  async markEmailChanged(accountId: string, at: string): Promise<void> {
    const a = this.byId.get(accountId);
    if (a) a.emailChangedAt = at;
  }
}

export class MemoryCredentialStore implements CredentialStore {
  private identities: Identity[] = [];
  private credentials = new Map<string, Credential>(); // key: `${accountId}:${method}`
  private publicKeys = new Map<string, PublicKey>();

  private credKey(accountId: string, method: AuthMethod) {
    return `${accountId}:${method}`;
  }

  async addIdentity(i: { accountId: string; method: AuthMethod; providerSubject?: string | null; credentialId?: string | null; id?: string }): Promise<Identity> {
    const identity: Identity = {
      id: i.id ?? crypto.randomUUID(),
      accountId: i.accountId,
      method: i.method,
      providerSubject: i.providerSubject ?? null,
      credentialId: i.credentialId ?? null,
      createdAt: new Date().toISOString(),
    };
    this.identities.push(identity);
    return { ...identity };
  }

  async getIdentityByProviderSubject(method: AuthMethod, subject: string): Promise<Identity | null> {
    const found = this.identities.find((i) => i.method === method && i.providerSubject === subject);
    return found ? { ...found } : null;
  }

  async getIdentityByCredentialId(credentialId: string): Promise<Identity | null> {
    const found = this.identities.find((i) => i.credentialId === credentialId);
    return found ? { ...found } : null;
  }

  async listIdentities(accountId: string): Promise<Identity[]> {
    return this.identities.filter((i) => i.accountId === accountId).map((i) => ({ ...i }));
  }

  async deleteIdentity(accountId: string, method: AuthMethod): Promise<void> {
    this.identities = this.identities.filter((i) => !(i.accountId === accountId && i.method === method));
  }

  async putCredential(c: { accountId: string; method: AuthMethod; wrappedPrivateKey: Uint8Array; kdfParams: unknown }): Promise<void> {
    this.credentials.set(this.credKey(c.accountId, c.method), { ...c, createdAt: new Date().toISOString() });
  }

  async getCredential(accountId: string, method: AuthMethod): Promise<Credential | null> {
    const c = this.credentials.get(this.credKey(accountId, method));
    return c ? { ...c } : null;
  }

  async listCredentials(accountId: string): Promise<{ method: AuthMethod; createdAt: string }[]> {
    return [...this.credentials.values()]
      .filter((c) => c.accountId === accountId)
      .map((c) => ({ method: c.method, createdAt: c.createdAt }));
  }

  async deleteCredential(accountId: string, method: AuthMethod): Promise<void> {
    this.credentials.delete(this.credKey(accountId, method));
  }

  async updatePasskeyCounter(accountId: string, counter: number): Promise<void> {
    const c = this.credentials.get(this.credKey(accountId, "passkey"));
    if (!c) return;
    c.kdfParams = { ...(c.kdfParams as Record<string, unknown>), counter };
  }

  async putPublicKey(p: { accountId: string; publicKeyJwk: unknown }): Promise<void> {
    this.publicKeys.set(p.accountId, { ...p, createdAt: new Date().toISOString() });
  }

  async getPublicKey(accountId: string): Promise<PublicKey | null> {
    const p = this.publicKeys.get(accountId);
    return p ? { ...p } : null;
  }
}

export class MemoryEnvelopeStore implements EnvelopeStore {
  private vaults = new Map<string, VaultRow>();
  private envelopes = new Map<string, Envelope>(); // key: `${vaultId}:${principalAccountId}`

  private envKey(vaultId: string, principalAccountId: string) {
    return `${vaultId}:${principalAccountId}`;
  }

  async createVault(v: { vaultId: string; ownerAccountId: string; r2Key: string; hd1Version: number }): Promise<VaultRow> {
    const row: VaultRow = { ...v, rotationPending: false, orgRecoveryRevokedAt: null, rotationStagingR2Key: null };
    this.vaults.set(v.vaultId, row);
    return { ...row };
  }

  async getVault(vaultId: string): Promise<VaultRow | null> {
    const v = this.vaults.get(vaultId);
    return v ? { ...v } : null;
  }

  async getVaultByR2Key(r2Key: string): Promise<VaultRow | null> {
    for (const v of this.vaults.values()) if (v.r2Key === r2Key) return { ...v };
    return null;
  }

  async getVaultByStagingR2Key(r2Key: string): Promise<VaultRow | null> {
    for (const v of this.vaults.values()) if (v.rotationStagingR2Key === r2Key) return { ...v };
    return null;
  }

  async listVaultsForOwner(ownerAccountId: string): Promise<VaultRow[]> {
    return [...this.vaults.values()].filter((v) => v.ownerAccountId === ownerAccountId).map((v) => ({ ...v }));
  }

  async setRotationPending(vaultId: string, pending: boolean): Promise<void> {
    const v = this.vaults.get(vaultId);
    if (v) v.rotationPending = pending;
  }

  async setRotationStaging(vaultId: string, r2Key: string | null): Promise<void> {
    const v = this.vaults.get(vaultId);
    if (v) v.rotationStagingR2Key = r2Key;
  }

  async setOrgRecoveryRevoked(vaultId: string, at: string | null): Promise<void> {
    const v = this.vaults.get(vaultId);
    if (v) v.orgRecoveryRevokedAt = at;
  }

  async putEnvelope(e: { vaultId: string; principalAccountId: string; wrappedDek: Uint8Array; ephemeralPublicKeyJwk: unknown; createdBy: string }): Promise<void> {
    this.envelopes.set(this.envKey(e.vaultId, e.principalAccountId), { ...e, createdAt: new Date().toISOString() });
  }

  async replaceEnvelopes(vaultId: string, envelopes: EnvelopeInput[], createdBy: string): Promise<void> {
    for (const key of [...this.envelopes.keys()]) if (key.startsWith(`${vaultId}:`)) this.envelopes.delete(key);
    const createdAt = new Date().toISOString();
    for (const e of envelopes) {
      this.envelopes.set(this.envKey(vaultId, e.principalAccountId), { vaultId, createdBy, createdAt, ...e });
    }
  }

  async commitRotation(vaultId: string, newR2Key: string, envelopes: EnvelopeInput[], createdBy: string): Promise<void> {
    await this.replaceEnvelopes(vaultId, envelopes, createdBy);
    const v = this.vaults.get(vaultId);
    if (v) {
      v.r2Key = newR2Key;
      v.rotationStagingR2Key = null;
      v.rotationPending = false;
    }
  }

  async getEnvelopeRow(vaultId: string, principalAccountId: string): Promise<Envelope | null> {
    const e = this.envelopes.get(this.envKey(vaultId, principalAccountId));
    return e ? { ...e } : null;
  }

  async listEnvelopesForVault(vaultId: string): Promise<Envelope[]> {
    return [...this.envelopes.values()].filter((e) => e.vaultId === vaultId).map((e) => ({ ...e }));
  }

  async listEnvelopesForPrincipal(principalAccountId: string): Promise<Envelope[]> {
    return [...this.envelopes.values()].filter((e) => e.principalAccountId === principalAccountId).map((e) => ({ ...e }));
  }

  async deleteEnvelope(vaultId: string, principalAccountId: string): Promise<void> {
    this.envelopes.delete(this.envKey(vaultId, principalAccountId));
  }
}

export class MemoryProviderLinkStore implements ProviderLinkStore {
  private links = new Map<string, ProviderLink>();

  async create(l: { ownerAccountId: string; providerAccountId: string; role: ProviderKind; status?: LinkStatus; consentRef?: string | null; grantedBy: string; expiresAt?: string | null; id?: string }): Promise<ProviderLink> {
    const link: ProviderLink = {
      id: l.id ?? crypto.randomUUID(),
      ownerAccountId: l.ownerAccountId,
      providerAccountId: l.providerAccountId,
      role: l.role,
      status: l.status ?? "invited",
      consentRef: l.consentRef ?? null,
      grantedBy: l.grantedBy,
      grantedAt: new Date().toISOString(),
      expiresAt: l.expiresAt ?? null,
    };
    this.links.set(link.id, link);
    return { ...link };
  }

  async updateStatus(id: string, status: LinkStatus): Promise<void> {
    const l = this.links.get(id);
    if (l) l.status = status;
  }

  async grantSupport(id: string, opts: { expiresAt: string | null; consentRef?: string | null }): Promise<void> {
    const l = this.links.get(id);
    if (!l) return;
    l.status = "active";
    l.expiresAt = opts.expiresAt;
    l.consentRef = opts.consentRef ?? null;
  }

  async get(id: string): Promise<ProviderLink | null> {
    const l = this.links.get(id);
    return l ? { ...l } : null;
  }

  async listForOwner(ownerAccountId: string): Promise<ProviderLink[]> {
    return [...this.links.values()].filter((l) => l.ownerAccountId === ownerAccountId).map((l) => ({ ...l }));
  }

  async listForProvider(providerAccountId: string): Promise<ProviderLink[]> {
    return [...this.links.values()].filter((l) => l.providerAccountId === providerAccountId).map((l) => ({ ...l }));
  }

  async getActive(ownerAccountId: string, providerAccountId: string): Promise<ProviderLink | null> {
    const link = [...this.links.values()].find(
      (l) => l.ownerAccountId === ownerAccountId && l.providerAccountId === providerAccountId
    );
    if (!link || link.status !== "active") return null;
    if (link.expiresAt && Date.parse(link.expiresAt) <= Date.now()) return null;
    return { ...link };
  }
}

export class MemoryAuditStore implements AuditStore {
  private events: AccessEvent[] = [];

  async insertAccessEvent(e: { actorAccountId: string; subjectAccountId: string; vaultId?: string | null; action: string; consentRef?: string | null; meta?: unknown; id?: string }): Promise<AccessEvent> {
    const event: AccessEvent = {
      id: e.id ?? crypto.randomUUID(),
      actorAccountId: e.actorAccountId,
      subjectAccountId: e.subjectAccountId,
      vaultId: e.vaultId ?? null,
      action: e.action,
      consentRef: e.consentRef ?? null,
      meta: e.meta ?? {},
      createdAt: new Date().toISOString(),
    };
    this.events.push(event);
    return { ...event };
  }

  async listAccessEventsForSubject(subjectAccountId: string): Promise<AccessEvent[]> {
    return this.events.filter((e) => e.subjectAccountId === subjectAccountId).map((e) => ({ ...e }));
  }
}
