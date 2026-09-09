import type { D1Database } from "./types";
import type { Account, LifecycleStage, ProviderKind, UnitSystem } from "../../stores";
export type { Account };

interface AccountRow {
  id: string;
  email: string | null;
  email_confirmed: number;
  display_name: string;
  lifecycle_stage: LifecycleStage;
  provider_kind: ProviderKind | null;
  unit_system: UnitSystem | null;
  created_at: string;
  deleted_at?: string | null;
  email_changed_at?: string | null;
}
function mapAccount(r: AccountRow): Account {
  return {
    id: r.id,
    email: r.email,
    emailConfirmed: r.email_confirmed === 1,
    displayName: r.display_name,
    lifecycleStage: r.lifecycle_stage,
    providerKind: r.provider_kind,
    unitSystem: r.unit_system,
    createdAt: r.created_at,
    deletedAt: r.deleted_at ?? null,
    emailChangedAt: r.email_changed_at ?? null,
  };
}

export async function createAccount(
  db: D1Database,
  a: { id: string; displayName: string; email?: string | null; lifecycleStage?: LifecycleStage; providerKind?: ProviderKind | null }
): Promise<Account> {
  const createdAt = new Date().toISOString();
  const email = a.email ?? null;
  const lifecycleStage = a.lifecycleStage ?? "active";
  const providerKind = a.providerKind ?? null;
  await db
    .prepare(
      "INSERT INTO accounts (id, email, email_confirmed, display_name, lifecycle_stage, provider_kind, created_at) VALUES (?, ?, 0, ?, ?, ?, ?)"
    )
    .bind(a.id, email, a.displayName, lifecycleStage, providerKind, createdAt)
    .run();
  return {
    id: a.id,
    email,
    emailConfirmed: false,
    displayName: a.displayName,
    lifecycleStage,
    providerKind,
    unitSystem: null,
    createdAt,
    deletedAt: null,
    emailChangedAt: null,
  };
}

export async function getAccount(db: D1Database, id: string): Promise<Account | null> {
  const row = await db.prepare("SELECT * FROM accounts WHERE id = ?").bind(id).first<AccountRow>();
  return row ? mapAccount(row) : null;
}

export async function getAccountByEmail(db: D1Database, email: string): Promise<Account | null> {
  const row = await db.prepare("SELECT * FROM accounts WHERE email = ?").bind(email).first<AccountRow>();
  return row ? mapAccount(row) : null;
}

/**
 * The instant before which this account's session cookies are no longer accepted, or null.
 *
 * Read on every authenticated request (see `requireSession`). One indexed lookup by primary
 * key is what buys revocability: the cookie is self-contained, so without a server-side fact to
 * check against, nothing short of rotating SESSION_SECRET for the entire deployment can invalidate one.
 */
export async function sessionsValidFrom(db: D1Database, accountId: string): Promise<number | null> {
  const row = await db.prepare("SELECT sessions_valid_from FROM accounts WHERE id = ?").bind(accountId).first<{ sessions_valid_from: string | null }>();
  // A cookie for an account that no longer exists is not merely un-revoked, it is unusable. Returning
  // Infinity rather than null makes deletion revoke by construction instead of by omission.
  if (!row) return Number.POSITIVE_INFINITY;
  return row.sessions_valid_from ? Math.floor(Date.parse(row.sessions_valid_from) / 1000) : null;
}

/**
 * Invalidates every session cookie already issued for this account.
 *
 * Called on logout and after any change to how the account is authenticated — a replaced password, a
 * removed passkey, a changed email. Those were the mutations that made a stolen cookie permanent:
 * they changed the credential and left every existing session running.
 *
 * Truncated to the second, and the rule is `iat >= validFrom`, so a cookie minted in the SAME second
 * as the revocation survives. That window is deliberate and cannot be closed without a per-session
 * id: the cookie's `iat` has one-second resolution, so a cookie minted just before the revocation and
 * one minted just after — by the login that immediately follows a logout — are indistinguishable.
 * Rounding the other way would reject the new session instead, which trades a one-second exposure for
 * a user who cannot log back in.
 */
export async function revokeSessions(db: D1Database, accountId: string): Promise<void> {
  await db
    .prepare("UPDATE accounts SET sessions_valid_from = ? WHERE id = ?")
    .bind(new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(), accountId)
    .run();
}

export async function setEmailConfirmed(db: D1Database, id: string, confirmed: boolean): Promise<void> {
  await db.prepare("UPDATE accounts SET email_confirmed = ? WHERE id = ?").bind(confirmed ? 1 : 0, id).run();
}

export async function setLifecycleStage(db: D1Database, id: string, stage: LifecycleStage): Promise<void> {
  await db.prepare("UPDATE accounts SET lifecycle_stage = ? WHERE id = ?").bind(stage, id).run();
}

export async function updateAccountProfile(
  db: D1Database,
  id: string,
  updates: { email?: string | null; displayName?: string; unitSystem?: UnitSystem | null }
): Promise<void> {
  const sets: string[] = [];
  const values: unknown[] = [];
  if (updates.email !== undefined) {
    sets.push("email = ?");
    values.push(updates.email);
  }
  if (updates.displayName !== undefined) {
    sets.push("display_name = ?");
    values.push(updates.displayName);
  }
  if (updates.unitSystem !== undefined) {
    sets.push("unit_system = ?");
    values.push(updates.unitSystem);
  }
  if (sets.length === 0) return;
  values.push(id);
  await db.prepare(`UPDATE accounts SET ${sets.join(", ")} WHERE id = ?`).bind(...values).run();
}

/**
 * Nulls every personal field and stamps `deleted_at`, leaving an opaque row behind. See the migration
 * for why the row survives at all.
 */
export async function tombstoneAccount(db: D1Database, accountId: string, at: string): Promise<void> {
  await db
    .prepare(
      "UPDATE accounts SET email = NULL, email_confirmed = 0, display_name = '', lifecycle_stage = 'churned', provider_kind = NULL, unit_system = NULL, deleted_at = ? WHERE id = ?",
    )
    .bind(at, accountId)
    .run();
}

/**
 * Stamps when the account's email address changed.
 *
 * Read by the recovery routes, which refuse to issue a grant while the address is still new: a stolen
 * cookie that repoints the mailbox should not be able to convert that into a recovery code minutes
 * later. See RECOVERY.md and migrations/0009.
 */
export async function markEmailChanged(db: D1Database, accountId: string, at: string): Promise<void> {
  await db.prepare("UPDATE accounts SET email_changed_at = ? WHERE id = ?").bind(at, accountId).run();
}
