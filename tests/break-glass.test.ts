import { describe, it, expect } from "vitest";
import { grantBreakGlass, checkBreakGlass, revokeBreakGlass, type BreakGlassPolicy } from "../break-glass";
import type { AccessEvent, LinkStatus, ProviderLink } from "../stores";

// Pure-logic tests against fakes, not a real store: break-glass.ts's job is the TTL-clamp/
// expiry/idempotent-revoke logic, not store wiring.

const POLICY: BreakGlassPolicy = { defaultTtlHours: 72, maxTtlHours: 720 };

function makeLink(overrides: Partial<ProviderLink> = {}): ProviderLink {
  return {
    id: "link-1",
    patientAccountId: "patient-1",
    providerAccountId: "provider-1",
    role: "support",
    status: "invited",
    consentRef: null,
    grantedBy: "patient-1",
    grantedAt: new Date().toISOString(),
    expiresAt: null,
    ...overrides,
  };
}

class FakeLinkStore {
  links = new Map<string, ProviderLink>();
  constructor(seed: ProviderLink[]) {
    for (const l of seed) this.links.set(l.id, l);
  }
  async get(id: string) {
    return this.links.get(id) ?? null;
  }
  async grantSupport(id: string, opts: { expiresAt: string | null; consentRef?: string | null }) {
    const l = this.links.get(id);
    if (!l) return;
    this.links.set(id, { ...l, status: "active", expiresAt: opts.expiresAt, consentRef: opts.consentRef ?? null });
  }
  async updateStatus(id: string, status: LinkStatus) {
    const l = this.links.get(id);
    if (!l) return;
    this.links.set(id, { ...l, status });
  }
}

class FakeAuditStore {
  events: Partial<AccessEvent>[] = [];
  async insertAccessEvent(e: Partial<AccessEvent>): Promise<AccessEvent> {
    this.events.push(e);
    return { id: "evt", createdAt: new Date().toISOString(), consentRef: null, meta: null, ...e } as AccessEvent;
  }
  async listAccessEventsForSubject(): Promise<AccessEvent[]> {
    return this.events as AccessEvent[];
  }
}

class FakeEnvelopeStore {
  envelopes = new Set<string>();
  deleteCalls = 0;
  rotationPending = new Map<string, boolean>();
  private key(vaultId: string, principalAccountId: string) {
    return `${vaultId}:${principalAccountId}`;
  }
  async putEnvelope(e: { vaultId: string; principalAccountId: string }) {
    this.envelopes.add(this.key(e.vaultId, e.principalAccountId));
  }
  async deleteEnvelope(vaultId: string, principalAccountId: string) {
    this.deleteCalls++;
    this.envelopes.delete(this.key(vaultId, principalAccountId));
  }
  async setRotationPending(vaultId: string, pending: boolean) {
    this.rotationPending.set(vaultId, pending);
  }
}

describe("grantBreakGlass", () => {
  it("clamps a requested TTL to the policy max and stamps a prefixed consent ref", async () => {
    const links = new FakeLinkStore([makeLink()]);
    const audit = new FakeAuditStore();
    const before = Date.now();

    const result = await grantBreakGlass(
      { links, audit },
      {
        linkId: "link-1",
        approverAccountId: "patient-1",
        requestedTtlHours: 999999,
        policy: POLICY,
        consentPrefix: "patient-approved",
        auditAction: "support_access_granted",
        buildAuditMeta: (expiresAt, link) => ({ providerAccountId: link.providerAccountId, expiresAt }),
      }
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const expiresAt = new Date(result.expiresAt).getTime();
    expect(expiresAt).toBeLessThanOrEqual(before + POLICY.maxTtlHours * 3600 * 1000 + 5000);
    expect(expiresAt).toBeGreaterThan(before + (POLICY.maxTtlHours - 1) * 3600 * 1000);
    expect((await links.get("link-1"))?.status).toBe("active");
    expect(audit.events[0]?.consentRef).toMatch(/^patient-approved:/);
  });

  it("falls back to the default TTL when none is requested", async () => {
    const links = new FakeLinkStore([makeLink()]);
    const before = Date.now();

    const result = await grantBreakGlass(
      { links, audit: new FakeAuditStore() },
      {
        linkId: "link-1",
        approverAccountId: "patient-1",
        requestedTtlHours: undefined,
        policy: POLICY,
        consentPrefix: "provider-approved",
        auditAction: "support_provider_access_granted",
        buildAuditMeta: (expiresAt, link) => ({ supportAccountId: link.providerAccountId, expiresAt }),
      }
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const expiresAt = new Date(result.expiresAt).getTime();
    expect(expiresAt).toBeLessThanOrEqual(before + POLICY.defaultTtlHours * 3600 * 1000 + 5000);
    expect(expiresAt).toBeGreaterThan(before + (POLICY.defaultTtlHours - 1) * 3600 * 1000);
  });

  it("rejects a link that isn't the approver's own pending support request", async () => {
    const links = new FakeLinkStore([makeLink({ patientAccountId: "someone-else" })]);
    const result = await grantBreakGlass(
      { links, audit: new FakeAuditStore() },
      {
        linkId: "link-1",
        approverAccountId: "patient-1",
        requestedTtlHours: undefined,
        policy: POLICY,
        consentPrefix: "patient-approved",
        auditAction: "support_access_granted",
        buildAuditMeta: (expiresAt) => ({ expiresAt }),
      }
    );
    expect(result).toEqual({ ok: false, error: "no_pending_link" });
  });

  it("writes an envelope and audits its vaultId only when one is supplied", async () => {
    const links = new FakeLinkStore([makeLink()]);
    const envelopes = new FakeEnvelopeStore();
    const audit = new FakeAuditStore();

    await grantBreakGlass(
      { links, audit, envelopes },
      {
        linkId: "link-1",
        approverAccountId: "patient-1",
        requestedTtlHours: undefined,
        policy: POLICY,
        consentPrefix: "patient-approved",
        auditAction: "support_access_granted",
        envelope: { vaultId: "vault-1", wrappedDek: new Uint8Array([1]), ephemeralPublicKeyJwk: {} },
        buildAuditMeta: (expiresAt, link) => ({ providerAccountId: link.providerAccountId, expiresAt }),
      }
    );

    expect(envelopes.envelopes.has("vault-1:provider-1")).toBe(true);
    expect(audit.events[0]?.vaultId).toBe("vault-1");

    const links2 = new FakeLinkStore([makeLink()]);
    const audit2 = new FakeAuditStore();
    await grantBreakGlass(
      { links: links2, audit: audit2 },
      {
        linkId: "link-1",
        approverAccountId: "patient-1",
        requestedTtlHours: undefined,
        policy: POLICY,
        consentPrefix: "provider-approved",
        auditAction: "support_provider_access_granted",
        buildAuditMeta: (expiresAt, link) => ({ supportAccountId: link.providerAccountId, expiresAt }),
      }
    );
    expect(audit2.events[0]?.vaultId).toBeNull();
  });
});

describe("checkBreakGlass", () => {
  it("passes through an unexpired grant with no side effects", async () => {
    const links = new FakeLinkStore([makeLink({ status: "active", expiresAt: new Date(Date.now() + 3600_000).toISOString() })]);
    const audit = new FakeAuditStore();
    const result = await checkBreakGlass(
      { links, audit },
      {
        link: (await links.get("link-1"))!,
        actorAccountId: "provider-1",
        subjectAccountId: "patient-1",
        vaultId: "vault-1",
        expiredAuditAction: "support_access_expired",
      }
    );
    expect(result).toEqual({ ok: true });
    expect(audit.events).toHaveLength(0);
    expect((await links.get("link-1"))?.status).toBe("active");
  });

  it("self-revokes and audits an expired grant, running onExpire first", async () => {
    const expiredLink = makeLink({ status: "active", expiresAt: new Date(Date.now() - 1000).toISOString(), consentRef: "patient-approved:x" });
    const links = new FakeLinkStore([expiredLink]);
    const audit = new FakeAuditStore();
    const envelopes = new FakeEnvelopeStore();
    await envelopes.putEnvelope({ vaultId: "vault-1", principalAccountId: "provider-1" });

    const result = await checkBreakGlass(
      { links, audit },
      {
        link: expiredLink,
        actorAccountId: "provider-1",
        subjectAccountId: "patient-1",
        vaultId: "vault-1",
        expiredAuditAction: "support_access_expired",
        onExpire: async () => {
          await envelopes.deleteEnvelope("vault-1", "provider-1");
          await envelopes.setRotationPending("vault-1", true);
        },
      }
    );

    expect(result).toEqual({ ok: false, error: "expired" });
    expect((await links.get("link-1"))?.status).toBe("revoked");
    expect(envelopes.envelopes.has("vault-1:provider-1")).toBe(false);
    expect(envelopes.rotationPending.get("vault-1")).toBe(true);
    expect(audit.events[0]).toMatchObject({ action: "support_access_expired", consentRef: "patient-approved:x" });
  });
});

describe("revokeBreakGlass", () => {
  it("deletes the envelope, marks the link revoked, and audits when an auditAction is given", async () => {
    const links = new FakeLinkStore([makeLink({ status: "active" })]);
    const audit = new FakeAuditStore();
    const envelopes = new FakeEnvelopeStore();
    await envelopes.putEnvelope({ vaultId: "vault-1", principalAccountId: "provider-1" });

    await revokeBreakGlass(
      { links, audit, envelopes },
      {
        linkId: "link-1",
        actorAccountId: "patient-1",
        subjectAccountId: "patient-1",
        providerAccountId: "provider-1",
        vaultId: "vault-1",
        auditAction: "support_access_denied",
        auditMeta: { providerAccountId: "provider-1" },
      }
    );

    expect((await links.get("link-1"))?.status).toBe("revoked");
    expect(envelopes.envelopes.has("vault-1:provider-1")).toBe(false);
    expect(audit.events).toHaveLength(1);
  });

  it("skips the audit when no auditAction is given (a clinician link)", async () => {
    const links = new FakeLinkStore([makeLink({ role: "clinician", status: "active" })]);
    const audit = new FakeAuditStore();
    await revokeBreakGlass(
      { links, audit },
      {
        linkId: "link-1",
        actorAccountId: "patient-1",
        subjectAccountId: "patient-1",
        providerAccountId: "provider-1",
        vaultId: null,
      }
    );
    expect((await links.get("link-1"))?.status).toBe("revoked");
    expect(audit.events).toHaveLength(0);
  });

  it("is idempotent: a second revoke of an already-revoked link doesn't throw", async () => {
    const links = new FakeLinkStore([makeLink({ status: "active" })]);
    const audit = new FakeAuditStore();
    const envelopes = new FakeEnvelopeStore();
    await envelopes.putEnvelope({ vaultId: "vault-1", principalAccountId: "provider-1" });

    const opts = {
      linkId: "link-1",
      actorAccountId: "patient-1",
      subjectAccountId: "patient-1",
      providerAccountId: "provider-1",
      vaultId: "vault-1",
      auditAction: "support_access_denied",
    };
    await revokeBreakGlass({ links, audit, envelopes }, opts);
    await expect(revokeBreakGlass({ links, audit, envelopes }, opts)).resolves.toBeUndefined();

    expect((await links.get("link-1"))?.status).toBe("revoked");
    expect(envelopes.deleteCalls).toBe(2);
    expect(envelopes.envelopes.has("vault-1:provider-1")).toBe(false);
  });
});
