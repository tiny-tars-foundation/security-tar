// D1 implementations of the storage-agnostic contracts in ../../stores.ts. Each method is a
// one-line delegation to the corresponding module in this directory — this file wires the portable
// interfaces to a D1 schema, and carries no logic of its own.

import type { D1Database } from "./types";
import type {
  AccountStore,
  CredentialStore,
  EnvelopeStore,
  ProviderLinkStore,
  AuditStore,
  EnvelopeInput,
} from "../../stores";

import * as accounts from "./accounts";
import * as credentials from "./credentials";
import * as vault from "./vault";
import * as providers from "./providers";
import * as audit from "./audit";

export type { D1Database, D1PreparedStatement, toBytes } from "./types";

export class D1AccountStore implements AccountStore {
  constructor(private db: D1Database) {}
  create(a: Parameters<AccountStore["create"]>[0]) {
    return accounts.createAccount(this.db, a);
  }
  get(id: string) {
    return accounts.getAccount(this.db, id);
  }
  getByEmail(email: string) {
    return accounts.getAccountByEmail(this.db, email);
  }
  sessionsValidFrom(accountId: string) {
    return accounts.sessionsValidFrom(this.db, accountId);
  }
  revokeSessions(accountId: string) {
    return accounts.revokeSessions(this.db, accountId);
  }
  setEmailConfirmed(id: string, confirmed: boolean) {
    return accounts.setEmailConfirmed(this.db, id, confirmed);
  }
  setLifecycleStage(id: string, stage: Parameters<AccountStore["setLifecycleStage"]>[1]) {
    return accounts.setLifecycleStage(this.db, id, stage);
  }
  updateProfile(id: string, updates: Parameters<AccountStore["updateProfile"]>[1]) {
    return accounts.updateAccountProfile(this.db, id, updates);
  }
  tombstone(accountId: string, at: string) {
    return accounts.tombstoneAccount(this.db, accountId, at);
  }
  markEmailChanged(accountId: string, at: string) {
    return accounts.markEmailChanged(this.db, accountId, at);
  }
}

export class D1CredentialStore implements CredentialStore {
  constructor(private db: D1Database) {}
  addIdentity(i: Parameters<CredentialStore["addIdentity"]>[0]) {
    return credentials.addIdentity(this.db, i);
  }
  getIdentityByProviderSubject(method: Parameters<CredentialStore["getIdentityByProviderSubject"]>[0], subject: string) {
    return credentials.getIdentityByProviderSubject(this.db, method, subject);
  }
  getIdentityByCredentialId(credentialId: string) {
    return credentials.getIdentityByCredentialId(this.db, credentialId);
  }
  listIdentities(accountId: string) {
    return credentials.listIdentities(this.db, accountId);
  }
  deleteIdentity(accountId: string, method: Parameters<CredentialStore["deleteIdentity"]>[1]) {
    return credentials.deleteIdentity(this.db, accountId, method);
  }
  putCredential(c: Parameters<CredentialStore["putCredential"]>[0]) {
    return credentials.putCredential(this.db, c);
  }
  getCredential(accountId: string, method: Parameters<CredentialStore["getCredential"]>[1]) {
    return credentials.getCredential(this.db, accountId, method);
  }
  listCredentials(accountId: string) {
    return credentials.listCredentials(this.db, accountId);
  }
  deleteCredential(accountId: string, method: Parameters<CredentialStore["deleteCredential"]>[1]) {
    return credentials.deleteCredential(this.db, accountId, method);
  }
  updatePasskeyCounter(accountId: string, counter: number) {
    return credentials.updatePasskeyCounter(this.db, accountId, counter);
  }
  putPublicKey(p: Parameters<CredentialStore["putPublicKey"]>[0]) {
    return credentials.putPublicKey(this.db, p);
  }
  getPublicKey(accountId: string) {
    return credentials.getPublicKey(this.db, accountId);
  }
}

export class D1EnvelopeStore implements EnvelopeStore {
  constructor(private db: D1Database) {}
  createVault(v: Parameters<EnvelopeStore["createVault"]>[0]) {
    return vault.createVault(this.db, v);
  }
  getVault(vaultId: string) {
    return vault.getVault(this.db, vaultId);
  }
  getVaultByR2Key(r2Key: string) {
    return vault.getVaultByR2Key(this.db, r2Key);
  }
  getVaultByStagingR2Key(r2Key: string) {
    return vault.getVaultByStagingR2Key(this.db, r2Key);
  }
  listVaultsForOwner(ownerAccountId: string) {
    return vault.listVaultsForOwner(this.db, ownerAccountId);
  }
  setRotationPending(vaultId: string, pending: boolean) {
    return vault.setRotationPending(this.db, vaultId, pending);
  }
  setRotationStaging(vaultId: string, r2Key: string | null) {
    return vault.setRotationStaging(this.db, vaultId, r2Key);
  }
  setOrgRecoveryRevoked(vaultId: string, at: string | null) {
    return vault.setOrgRecoveryRevoked(this.db, vaultId, at);
  }
  putEnvelope(e: Parameters<EnvelopeStore["putEnvelope"]>[0]) {
    return vault.putEnvelope(this.db, e);
  }
  replaceEnvelopes(vaultId: string, envelopes: EnvelopeInput[], createdBy: string) {
    return vault.replaceEnvelopes(this.db, vaultId, envelopes, createdBy);
  }
  commitRotation(vaultId: string, newR2Key: string, envelopes: EnvelopeInput[], createdBy: string) {
    return vault.commitRotation(this.db, vaultId, newR2Key, envelopes, createdBy);
  }
  getEnvelopeRow(vaultId: string, principalAccountId: string) {
    return vault.getEnvelopeRow(this.db, vaultId, principalAccountId);
  }
  listEnvelopesForVault(vaultId: string) {
    return vault.listEnvelopesForVault(this.db, vaultId);
  }
  listEnvelopesForPrincipal(principalAccountId: string) {
    return vault.listEnvelopesForPrincipal(this.db, principalAccountId);
  }
  deleteEnvelope(vaultId: string, principalAccountId: string) {
    return vault.deleteEnvelope(this.db, vaultId, principalAccountId);
  }
}

export class D1ProviderLinkStore implements ProviderLinkStore {
  constructor(private db: D1Database) {}
  create(l: Parameters<ProviderLinkStore["create"]>[0]) {
    return providers.createProviderLink(this.db, l);
  }
  updateStatus(id: string, status: Parameters<ProviderLinkStore["updateStatus"]>[1]) {
    return providers.updateProviderLinkStatus(this.db, id, status);
  }
  grantSupport(id: string, opts: Parameters<ProviderLinkStore["grantSupport"]>[1]) {
    return providers.grantSupportLink(this.db, id, opts);
  }
  get(id: string) {
    return providers.getProviderLink(this.db, id);
  }
  listForOwner(ownerAccountId: string) {
    return providers.listProvidersForOwner(this.db, ownerAccountId);
  }
  listForProvider(providerAccountId: string) {
    return providers.listOwnersForProvider(this.db, providerAccountId);
  }
  getActive(ownerAccountId: string, providerAccountId: string) {
    return providers.getActiveProviderLink(this.db, ownerAccountId, providerAccountId);
  }
}

export class D1AuditStore implements AuditStore {
  constructor(private db: D1Database) {}
  insertAccessEvent(e: Parameters<AuditStore["insertAccessEvent"]>[0]) {
    return audit.insertAccessEvent(this.db, e);
  }
  listAccessEventsForSubject(subjectAccountId: string) {
    return audit.listAccessEventsForSubject(this.db, subjectAccountId);
  }
}
