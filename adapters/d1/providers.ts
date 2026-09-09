import type { D1Database } from "./types";
import type { ProviderKind, LinkStatus, ProviderLink } from "../../stores";
export type { ProviderLink };

interface ProviderLinkRow {
  id: string;
  patient_account_id: string;
  provider_account_id: string;
  role: ProviderKind;
  status: LinkStatus;
  consent_ref: string | null;
  granted_by: string;
  granted_at: string;
  expires_at: string | null;
}
function mapProviderLink(r: ProviderLinkRow): ProviderLink {
  return {
    id: r.id,
    patientAccountId: r.patient_account_id,
    providerAccountId: r.provider_account_id,
    role: r.role,
    status: r.status,
    consentRef: r.consent_ref,
    grantedBy: r.granted_by,
    grantedAt: r.granted_at,
    expiresAt: r.expires_at ?? null,
  };
}

export async function createProviderLink(
  db: D1Database,
  l: {
    patientAccountId: string;
    providerAccountId: string;
    role: ProviderKind;
    status?: LinkStatus;
    consentRef?: string | null;
    grantedBy: string;
    expiresAt?: string | null;
    id?: string;
  }
): Promise<ProviderLink> {
  const id = l.id ?? crypto.randomUUID();
  const status = l.status ?? "invited";
  const consentRef = l.consentRef ?? null;
  const expiresAt = l.expiresAt ?? null;
  const grantedAt = new Date().toISOString();
  await db
    .prepare(
      "INSERT INTO provider_links (id, patient_account_id, provider_account_id, role, status, consent_ref, granted_by, granted_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(id, l.patientAccountId, l.providerAccountId, l.role, status, consentRef, l.grantedBy, grantedAt, expiresAt)
    .run();
  return {
    id,
    patientAccountId: l.patientAccountId,
    providerAccountId: l.providerAccountId,
    role: l.role,
    status,
    consentRef,
    grantedBy: l.grantedBy,
    grantedAt,
    expiresAt,
  };
}

export async function updateProviderLinkStatus(db: D1Database, id: string, status: LinkStatus): Promise<void> {
  await db.prepare("UPDATE provider_links SET status = ? WHERE id = ?").bind(status, id).run();
}

// An owner approving a support request: flip the link active, stamp its time-box + consent.
export async function grantSupportLink(
  db: D1Database,
  id: string,
  opts: { expiresAt: string | null; consentRef?: string | null }
): Promise<void> {
  await db
    .prepare("UPDATE provider_links SET status = 'active', expires_at = ?, consent_ref = ? WHERE id = ?")
    .bind(opts.expiresAt, opts.consentRef ?? null, id)
    .run();
}

export async function getProviderLink(db: D1Database, id: string): Promise<ProviderLink | null> {
  const row = await db.prepare("SELECT * FROM provider_links WHERE id = ?").bind(id).first<ProviderLinkRow>();
  return row ? mapProviderLink(row) : null;
}

export async function listProvidersForPatient(db: D1Database, patientAccountId: string): Promise<ProviderLink[]> {
  const { results } = await db
    .prepare("SELECT * FROM provider_links WHERE patient_account_id = ?")
    .bind(patientAccountId)
    .all<ProviderLinkRow>();
  return results.map(mapProviderLink);
}

export async function listPatientsForProvider(db: D1Database, providerAccountId: string): Promise<ProviderLink[]> {
  const { results } = await db
    .prepare("SELECT * FROM provider_links WHERE provider_account_id = ?")
    .bind(providerAccountId)
    .all<ProviderLinkRow>();
  return results.map(mapProviderLink);
}

export async function getActiveProviderLink(
  db: D1Database,
  patientAccountId: string,
  providerAccountId: string
): Promise<ProviderLink | null> {
  const link = await db
    .prepare("SELECT * FROM provider_links WHERE patient_account_id = ? AND provider_account_id = ?")
    .bind(patientAccountId, providerAccountId)
    .first<ProviderLinkRow>();
  if (!link || link.status !== "active") return null;
  // `expires_at` is set on time-boxed support grants and null for clinician links.
  if (link.expires_at && Date.parse(link.expires_at) <= Date.now()) return null;
  return mapProviderLink(link);
}
