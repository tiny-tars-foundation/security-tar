import type { D1Database } from "./types";
import { toBytes } from "./types";
import type { AuthMethod, Identity, Credential, PublicKey } from "../../stores";
export type { Identity, Credential, PublicKey };

interface IdentityRow {
  id: string;
  account_id: string;
  method: AuthMethod;
  provider_subject: string | null;
  credential_id: string | null;
  created_at: string;
}
function mapIdentity(r: IdentityRow): Identity {
  return {
    id: r.id,
    accountId: r.account_id,
    method: r.method,
    providerSubject: r.provider_subject,
    credentialId: r.credential_id,
    createdAt: r.created_at,
  };
}

export async function addIdentity(
  db: D1Database,
  i: { accountId: string; method: AuthMethod; providerSubject?: string | null; credentialId?: string | null; id?: string }
): Promise<Identity> {
  const id = i.id ?? crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const providerSubject = i.providerSubject ?? null;
  const credentialId = i.credentialId ?? null;
  await db
    .prepare(
      "INSERT INTO identities (id, account_id, method, provider_subject, credential_id, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(id, i.accountId, i.method, providerSubject, credentialId, createdAt)
    .run();
  return { id, accountId: i.accountId, method: i.method, providerSubject, credentialId, createdAt };
}

export async function getIdentityByProviderSubject(
  db: D1Database,
  method: AuthMethod,
  subject: string
): Promise<Identity | null> {
  const row = await db
    .prepare("SELECT * FROM identities WHERE method = ? AND provider_subject = ?")
    .bind(method, subject)
    .first<IdentityRow>();
  return row ? mapIdentity(row) : null;
}

export async function getIdentityByCredentialId(db: D1Database, credentialId: string): Promise<Identity | null> {
  const row = await db.prepare("SELECT * FROM identities WHERE credential_id = ?").bind(credentialId).first<IdentityRow>();
  return row ? mapIdentity(row) : null;
}

export async function listIdentities(db: D1Database, accountId: string): Promise<Identity[]> {
  const { results } = await db.prepare("SELECT * FROM identities WHERE account_id = ?").bind(accountId).all<IdentityRow>();
  return results.map(mapIdentity);
}

interface CredentialRow {
  account_id: string;
  method: AuthMethod;
  wrapped_private_key: unknown;
  kdf_params: string;
  created_at: string;
}
function mapCredential(r: CredentialRow): Credential {
  return {
    accountId: r.account_id,
    method: r.method,
    wrappedPrivateKey: toBytes(r.wrapped_private_key),
    kdfParams: JSON.parse(r.kdf_params),
    createdAt: r.created_at,
  };
}

export async function putCredential(
  db: D1Database,
  c: { accountId: string; method: AuthMethod; wrappedPrivateKey: Uint8Array; kdfParams: unknown }
): Promise<void> {
  const createdAt = new Date().toISOString();
  await db
    .prepare(
      "INSERT OR REPLACE INTO credentials (account_id, method, wrapped_private_key, kdf_params, created_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(c.accountId, c.method, c.wrappedPrivateKey, JSON.stringify(c.kdfParams), createdAt)
    .run();
}

export async function getCredential(db: D1Database, accountId: string, method: AuthMethod): Promise<Credential | null> {
  const row = await db
    .prepare("SELECT * FROM credentials WHERE account_id = ? AND method = ?")
    .bind(accountId, method)
    .first<CredentialRow>();
  return row ? mapCredential(row) : null;
}

// W44 P8 — the account's key-bearing methods (password/passkey/recovery), for the Account screen and the
// "don't orphan the vault key on remove" invariant. The credentials table is the source of truth (each
// row independently wraps the same private key); identities lacks a recovery row.
export async function listCredentials(db: D1Database, accountId: string): Promise<{ method: AuthMethod; createdAt: string }[]> {
  const { results } = await db
    .prepare("SELECT method, created_at FROM credentials WHERE account_id = ?")
    .bind(accountId)
    .all<{ method: AuthMethod; created_at: string }>();
  return results.map((r) => ({ method: r.method, createdAt: r.created_at }));
}

export async function deleteCredential(db: D1Database, accountId: string, method: AuthMethod): Promise<void> {
  await db.prepare("DELETE FROM credentials WHERE account_id = ? AND method = ?").bind(accountId, method).run();
}

export async function deleteIdentity(db: D1Database, accountId: string, method: AuthMethod): Promise<void> {
  await db.prepare("DELETE FROM identities WHERE account_id = ? AND method = ?").bind(accountId, method).run();
}

// W44 P3 — bump the passkey authenticator's signature counter after a successful login
// (replay-attack detection). Merges into the existing kdf_params rather than a raw column
// update so the wrapped key row stays a single INSERT OR REPLACE-shaped record.
export async function updatePasskeyCounter(db: D1Database, accountId: string, counter: number): Promise<void> {
  const cred = await getCredential(db, accountId, "passkey");
  if (!cred) return;
  const kdfParams = { ...(cred.kdfParams as Record<string, unknown>), counter };
  await db
    .prepare("UPDATE credentials SET kdf_params = ? WHERE account_id = ? AND method = 'passkey'")
    .bind(JSON.stringify(kdfParams), accountId)
    .run();
}

interface PublicKeyRow {
  account_id: string;
  public_key_jwk: string;
  created_at: string;
}
function mapPublicKey(r: PublicKeyRow): PublicKey {
  return { accountId: r.account_id, publicKeyJwk: JSON.parse(r.public_key_jwk), createdAt: r.created_at };
}

export async function putPublicKey(db: D1Database, p: { accountId: string; publicKeyJwk: unknown }): Promise<void> {
  const createdAt = new Date().toISOString();
  await db
    .prepare("INSERT OR REPLACE INTO public_keys (account_id, public_key_jwk, created_at) VALUES (?, ?, ?)")
    .bind(p.accountId, JSON.stringify(p.publicKeyJwk), createdAt)
    .run();
}

export async function getPublicKey(db: D1Database, accountId: string): Promise<PublicKey | null> {
  const row = await db.prepare("SELECT * FROM public_keys WHERE account_id = ?").bind(accountId).first<PublicKeyRow>();
  return row ? mapPublicKey(row) : null;
}
