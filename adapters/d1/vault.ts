import type { D1Database } from "./types";
import { toBytes } from "./types";
import type { VaultRow, Envelope } from "../../stores";
export type { VaultRow, Envelope };

// CRUD only. `getEnvelope()` — the version of this read that applies access POLICY (provider-link
// state, the org-recovery principal) — is app-specific and stays in the app's identity-vault.ts,
// built on top of `getEnvelopeRow`/`getVault` below. See stores.ts's own docstring on why policy
// doesn't belong in a portable adapter.

interface VaultRowRaw {
  vault_id: string;
  owner_account_id: string;
  r2_key: string;
  hd1_version: number;
  rotation_pending?: number;
  org_recovery_revoked_at?: string | null;
  rotation_staging_r2_key?: string | null;
}
function mapVault(r: VaultRowRaw): VaultRow {
  return {
    vaultId: r.vault_id,
    ownerAccountId: r.owner_account_id,
    r2Key: r.r2_key,
    hd1Version: r.hd1_version,
    rotationPending: r.rotation_pending === 1,
    orgRecoveryRevokedAt: r.org_recovery_revoked_at ?? null,
    rotationStagingR2Key: r.rotation_staging_r2_key ?? null,
  };
}

export async function setRotationPending(db: D1Database, vaultId: string, pending: boolean): Promise<void> {
  await db.prepare("UPDATE vaults SET rotation_pending = ? WHERE vault_id = ?").bind(pending ? 1 : 0, vaultId).run();
}

export async function setOrgRecoveryRevoked(db: D1Database, vaultId: string, at: string | null): Promise<void> {
  await db.prepare("UPDATE vaults SET org_recovery_revoked_at = ? WHERE vault_id = ?").bind(at, vaultId).run();
}

export async function createVault(
  db: D1Database,
  v: { vaultId: string; ownerAccountId: string; r2Key: string; hd1Version: number }
): Promise<VaultRow> {
  await db
    .prepare("INSERT INTO vaults (vault_id, owner_account_id, r2_key, hd1_version) VALUES (?, ?, ?, ?)")
    .bind(v.vaultId, v.ownerAccountId, v.r2Key, v.hd1Version)
    .run();
  return { ...v, rotationPending: false, orgRecoveryRevokedAt: null, rotationStagingR2Key: null };
}

export async function getVault(db: D1Database, vaultId: string): Promise<VaultRow | null> {
  const row = await db.prepare("SELECT * FROM vaults WHERE vault_id = ?").bind(vaultId).first<VaultRowRaw>();
  return row ? mapVault(row) : null;
}

/** The vault whose in-flight rotation has reserved this key. See `commitRotation`. */
export async function getVaultByStagingR2Key(db: D1Database, r2Key: string): Promise<VaultRow | null> {
  const row = await db.prepare("SELECT * FROM vaults WHERE rotation_staging_r2_key = ?").bind(r2Key).first<VaultRowRaw>();
  return row ? mapVault(row) : null;
}

export async function setRotationStaging(db: D1Database, vaultId: string, r2Key: string | null): Promise<void> {
  await db.prepare("UPDATE vaults SET rotation_staging_r2_key = ? WHERE vault_id = ?").bind(r2Key, vaultId).run();
}

export async function getVaultByR2Key(db: D1Database, r2Key: string): Promise<VaultRow | null> {
  const row = await db.prepare("SELECT * FROM vaults WHERE r2_key = ?").bind(r2Key).first<VaultRowRaw>();
  return row ? mapVault(row) : null;
}

export async function listVaultsForOwner(db: D1Database, ownerAccountId: string): Promise<VaultRow[]> {
  const { results } = await db.prepare("SELECT * FROM vaults WHERE owner_account_id = ?").bind(ownerAccountId).all<VaultRowRaw>();
  return results.map(mapVault);
}

interface EnvelopeRow {
  vault_id: string;
  principal_account_id: string;
  wrapped_dek: unknown;
  ephemeral_public_key_jwk: string;
  created_by: string;
  created_at: string;
}
function mapEnvelope(r: EnvelopeRow): Envelope {
  return {
    vaultId: r.vault_id,
    principalAccountId: r.principal_account_id,
    wrappedDek: toBytes(r.wrapped_dek),
    ephemeralPublicKeyJwk: JSON.parse(r.ephemeral_public_key_jwk),
    createdBy: r.created_by,
    createdAt: r.created_at,
  };
}

export async function putEnvelope(
  db: D1Database,
  e: { vaultId: string; principalAccountId: string; wrappedDek: Uint8Array; ephemeralPublicKeyJwk: unknown; createdBy: string }
): Promise<void> {
  const createdAt = new Date().toISOString();
  await db
    .prepare(
      "INSERT OR REPLACE INTO vault_envelopes (vault_id, principal_account_id, wrapped_dek, ephemeral_public_key_jwk, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(e.vaultId, e.principalAccountId, e.wrappedDek, JSON.stringify(e.ephemeralPublicKeyJwk), e.createdBy, createdAt)
    .run();
}

/**
 * Swap a vault's whole envelope set atomically.
 *
 * The rotation route used to delete every envelope in a loop and then build the replacements one at a
 * time, decoding each `wrappedDEK` as it went. Two ways that ended in an unrecoverable vault: a
 * malformed base64 string threw AFTER the deletes had committed, and a D1 failure partway through the
 * second loop left the set half-written. Either way the R2 blob stays encrypted under the new DEK
 * while no envelope anywhere can unwrap it — including the org recovery envelope, so there is no
 * second door. Nobody finds out until the next unlock fails.
 *
 * One batch, so D1 either applies the whole swap or none of it. Callers must still validate the
 * envelopes before calling: a decode that throws here would throw before the batch is submitted,
 * which is safe, but the caller owes the user a 400 rather than a 500.
 */
export async function replaceEnvelopes(
  db: D1Database,
  vaultId: string,
  envelopes: { principalAccountId: string; wrappedDek: Uint8Array; ephemeralPublicKeyJwk: unknown }[],
  createdBy: string,
): Promise<void> {
  const createdAt = new Date().toISOString();
  await db.batch([
    db.prepare("DELETE FROM vault_envelopes WHERE vault_id = ?").bind(vaultId),
    ...envelopes.map((e) =>
      db
        .prepare(
          "INSERT OR REPLACE INTO vault_envelopes (vault_id, principal_account_id, wrapped_dek, ephemeral_public_key_jwk, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(vaultId, e.principalAccountId, e.wrappedDek, JSON.stringify(e.ephemeralPublicKeyJwk), createdBy, createdAt)
    ),
  ]);
}

/**
 * The whole re-key, committed as one D1 batch: swap the envelope set AND repoint the vault at
 * the freshly-written object, in one implicit transaction.
 *
 * The atomicity is the point. The rotation used to re-encrypt IN PLACE — new DEK into the same r2
 * key, envelopes updated several network round trips later. Between those two writes the ciphertext
 * was readable only by a key held in one tab's memory, and a dropped connection there locked every
 * principal out of the record permanently. Writing to a new key makes this UPDATE the only moment
 * anything becomes true: before it, the old blob and the old envelopes still agree.
 *
 * The old object is deliberately left in R2 rather than deleted here. It is unreferenced and
 * undecryptable-by-design after the swap, and deleting it would put an irreversible step back inside
 * the window this function exists to close.
 */
export async function commitRotation(
  db: D1Database,
  vaultId: string,
  newR2Key: string,
  envelopes: { principalAccountId: string; wrappedDek: Uint8Array; ephemeralPublicKeyJwk: unknown }[],
  createdBy: string,
): Promise<void> {
  const createdAt = new Date().toISOString();
  await db.batch([
    db.prepare("DELETE FROM vault_envelopes WHERE vault_id = ?").bind(vaultId),
    ...envelopes.map((e) =>
      db
        .prepare(
          "INSERT OR REPLACE INTO vault_envelopes (vault_id, principal_account_id, wrapped_dek, ephemeral_public_key_jwk, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(vaultId, e.principalAccountId, e.wrappedDek, JSON.stringify(e.ephemeralPublicKeyJwk), createdBy, createdAt)
    ),
    db
      .prepare("UPDATE vaults SET r2_key = ?, rotation_staging_r2_key = NULL, rotation_pending = 0 WHERE vault_id = ?")
      .bind(newR2Key, vaultId),
  ]);
}

/**
 * The envelope row as stored, with NO access check. Use the app's `getEnvelope` unless you
 * specifically need the raw row (listing, rotation, administration) — this one answers "does a row
 * exist", which is not the same question as "may this principal open the vault".
 */
export async function getEnvelopeRow(db: D1Database, vaultId: string, principalAccountId: string): Promise<Envelope | null> {
  const row = await db
    .prepare("SELECT * FROM vault_envelopes WHERE vault_id = ? AND principal_account_id = ?")
    .bind(vaultId, principalAccountId)
    .first<EnvelopeRow>();
  return row ? mapEnvelope(row) : null;
}

export async function listEnvelopesForVault(db: D1Database, vaultId: string): Promise<Envelope[]> {
  const { results } = await db.prepare("SELECT * FROM vault_envelopes WHERE vault_id = ?").bind(vaultId).all<EnvelopeRow>();
  return results.map(mapEnvelope);
}

export async function listEnvelopesForPrincipal(db: D1Database, principalAccountId: string): Promise<Envelope[]> {
  const { results } = await db
    .prepare("SELECT * FROM vault_envelopes WHERE principal_account_id = ?")
    .bind(principalAccountId)
    .all<EnvelopeRow>();
  return results.map(mapEnvelope);
}

export async function deleteEnvelope(db: D1Database, vaultId: string, principalAccountId: string): Promise<void> {
  await db
    .prepare("DELETE FROM vault_envelopes WHERE vault_id = ? AND principal_account_id = ?")
    .bind(vaultId, principalAccountId)
    .run();
}
