import type { D1Database } from "./types";
import type { AccessEvent } from "../../stores";
export type { AccessEvent };

// AuditStore's two members only — PHI-access events. Lifecycle/CRM events and raw-object ownership
// bookkeeping are app-specific concerns that stay in the app's identity-audit.ts (see stores.ts's
// own docstring on AuditStore).

// FTC-HBNR (§I) PHI-access/disclosure audit log. Records WHO (actor) accessed WHOSE (subject)
// vault and WHY (action + consent_ref), so a breach can be scoped to affected individuals. NO PHI.
interface AccessEventRow {
  id: string;
  actor_account_id: string;
  subject_account_id: string;
  vault_id: string | null;
  action: string;
  consent_ref: string | null;
  meta: string;
  created_at: string;
}
function mapAccessEvent(r: AccessEventRow): AccessEvent {
  return {
    id: r.id,
    actorAccountId: r.actor_account_id,
    subjectAccountId: r.subject_account_id,
    vaultId: r.vault_id,
    action: r.action,
    consentRef: r.consent_ref,
    meta: JSON.parse(r.meta),
    createdAt: r.created_at,
  };
}

export async function insertAccessEvent(
  db: D1Database,
  e: { actorAccountId: string; subjectAccountId: string; vaultId?: string | null; action: string; consentRef?: string | null; meta?: unknown; id?: string }
): Promise<AccessEvent> {
  const id = e.id ?? crypto.randomUUID();
  const vaultId = e.vaultId ?? null;
  const consentRef = e.consentRef ?? null;
  const meta = e.meta ?? {};
  const createdAt = new Date().toISOString();
  await db
    .prepare(
      "INSERT INTO phi_access_events (id, actor_account_id, subject_account_id, vault_id, action, consent_ref, meta, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(id, e.actorAccountId, e.subjectAccountId, vaultId, e.action, consentRef, JSON.stringify(meta), createdAt)
    .run();
  return { id, actorAccountId: e.actorAccountId, subjectAccountId: e.subjectAccountId, vaultId, action: e.action, consentRef, meta, createdAt };
}

export async function listAccessEventsForSubject(db: D1Database, subjectAccountId: string): Promise<AccessEvent[]> {
  const { results } = await db
    .prepare("SELECT * FROM phi_access_events WHERE subject_account_id = ? ORDER BY created_at")
    .bind(subjectAccountId)
    .all<AccessEventRow>();
  return results.map(mapAccessEvent);
}
