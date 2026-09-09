import { encryptVaultV2 } from "./crypto";

// A VaultSink persists an already-encrypted vault blob under a vault id. The
// encryption boundary stays in the browser (saveVaultV2 encrypts); a sink only
// stores opaque ciphertext, never plaintext or a key.
export interface VaultSink {
  put(id: string, blob: Uint8Array): Promise<void>;
}

/**
 * The version of each vault blob this browser context last saw.
 *
 * Deliberately held HERE rather than threaded through callers. A real adopter typically has several
 * independent call sites that all persist through `saveVaultV2` — a queued-edit path plus things
 * like key rotation, background regeneration, imports, raw uploads and onboarding — and usually only
 * one of them goes through a save queue. Since the precondition is REQUIRED on the browser path, a
 * call site that forgot to pass an etag would not degrade — it would 428, i.e. an owner unable to
 * save their own record. Keeping the token where the
 * request is built makes every path correct by construction instead of by remembering.
 *
 * One entry per vault id, which is exactly the domain: a browser context has one current view of a
 * given blob.
 */
const etags = new Map<string, string>();

/** Record the version seen on a GET (or cleared, when a vault is closed). */
export function rememberVaultEtag(id: string, etag: string | null): void {
  if (etag) etags.set(id, etag);
  else etags.delete(id);
}

export function knownVaultEtag(id: string): string | null {
  return etags.get(id) ?? null;
}

/**
 * The save was refused because the blob moved since this context read it.
 *
 * Typed, not a string match: the caller must be able to tell "someone else edited this record" from
 * "the network is down", because the honest response to each is completely different.
 */
export class VaultConflictError extends Error {
  constructor(readonly serverEtag: string | null) {
    super("This record was changed in another tab or on another device.");
    this.name = "VaultConflictError";
  }
}

/**
 * One hook, so every save path reports a conflict — not just the queued one.
 *
 * Most real `saveVaultV2` call sites are direct `await`s outside any save queue (key rotation,
 * background regeneration, import, raw upload, onboarding). Wiring the conflict state through each
 * would be one chance to miss it per call site, and a missed one is an unhandled rejection on a
 * record someone owns. Every save funnels through this sink, so this is the one place that sees them all.
 * The error still throws afterwards, so existing per-path error handling is unchanged.
 */
let onConflict: ((e: VaultConflictError) => void) | null = null;
export function setVaultConflictHandler(fn: ((e: VaultConflictError) => void) | null): void {
  onConflict = fn;
}

// Dev-only sink: POSTs the blob to a local dev-server middleware, which writes it to disk.
// Absent from the deployed build — there is no such endpoint in production. The R2 sink below is
// the second implementation of this interface, for a real remote/mobile save.
export const localSink: VaultSink = {
  async put(id, blob) {
    const res = await fetch(`/__save-vault?id=${encodeURIComponent(id)}`, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: blob as BodyInit,
    });
    if (!res.ok) {
      throw new Error(`save failed (${res.status}): ${(await res.text()) || res.statusText}`);
    }
  },
};

// Remote sink: PUTs the encrypted blob to an R2-backed Pages Function.
// `/api/vault/{id}` only exists in the deployed build; the route guard checks the adopter's own
// session cookie (owner/granted-provider envelope check) — same-origin fetch sends it automatically.
// The Function stores opaque ciphertext — same as localSink, never plaintext or a key.
/**
 * One write at a time per vault, so the app never conflicts with ITSELF.
 *
 * `vaultSave` serializes the queued edit path, but six of `saveVaultV2`'s seven call sites bypass it
 * and `await` directly — so a user edit and a leaf-regen persist could be in flight together. Each
 * reads the version token when it builds its request, so the second would send one the first had
 * already superseded, and the guard would correctly report a conflict against a tab that is only
 * racing itself. CI found exactly that: five specs that save and then trigger a regen went red with
 * the conflict panel intercepting pointer events.
 *
 * Serializing HERE rather than in vaultSave is deliberate: this is the only place every write passes
 * through, and the version token lives here too — the token must be read after the previous write has
 * settled, which is precisely what a chain guarantees.
 */
const writeChains = new Map<string, Promise<void>>();

export const r2Sink: VaultSink = {
  put(id, blob) {
    const prev = writeChains.get(id) ?? Promise.resolve();
    // The `.catch` is on the READ, not the store: one failed write must not poison every later one,
    // while the failure still reaches its own caller through the promise returned below. Catching on
    // both sides would be redundant — and a redundant guard is one no test can distinguish, which is
    // how it was caught here.
    const next = prev.catch(() => {}).then(() => putConditional(id, blob));
    writeChains.set(id, next);
    return next;
  },
};

async function putConditional(id: string, blob: Uint8Array): Promise<void> {
  {
    const known = etags.get(id);
    const headers: Record<string, string> = { "Content-Type": "application/octet-stream" };
    // Either "replace exactly this version" or "create, and refuse if one already exists". Never
    // neither: the Function 428s an unconditional browser write, by design.
    if (known) headers["If-Match"] = known;
    else headers["If-None-Match"] = "*";

    const res = await fetch(`/api/vault/${encodeURIComponent(id)}`, { method: "PUT", headers, body: blob as BodyInit });

    if (res.status === 412) {
      // Adopt nothing yet — the caller decides. The server hands back the current version so a
      // resolution costs one round trip rather than two.
      const conflict = new VaultConflictError(res.headers.get("ETag"));
      onConflict?.(conflict);
      throw conflict;
    }
    if (!res.ok) {
      throw new Error(`save failed (${res.status}): ${(await res.text()) || res.statusText}`);
    }
    const newEtag = res.headers.get("ETag");
    if (newEtag) etags.set(id, newEtag);
  }
}

// Build-time selection: dev (vite) writes to disk via localSink; the deployed bundle (and the
// wrangler-pages-dev e2e harness) persists to R2 and never references /__save-vault.
export const vaultSink: VaultSink = import.meta.env.DEV ? localSink : r2Sink;

// Encrypt the vault under its DEK (HD1 v2 envelope) and persist. The DEK is the vault's
// random data key, unwrapped at login from the caller's key envelope; it stays in memory.
export async function saveVaultV2<T = Record<string, unknown>>(vault: T, id: string, dek: CryptoKey, sink: VaultSink): Promise<void> {
  const blob = await encryptVaultV2(vault, dek);
  await sink.put(id, blob);
}
