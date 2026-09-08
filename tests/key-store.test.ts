import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { putAccountKey, getAccountKey, clearAccountKey } from "../key-store";

// key-store.ts's whole reason to exist is the NON-EXTRACTABLE re-import in putAccountKey: the
// account private key survives a refresh, but an XSS payload cannot read its bytes back out. Drop
// the `false` argument and everything still works — the session resumes, the vault opens — while
// the property the module was written for is gone. That is the definition of a silent failure, so
// it is what these assert.
//
// IndexedDB is not implemented by Node/vitest, so the store itself is a minimal in-memory shim
// (below). Nothing being asserted lives in the shim: the CryptoKey and every operation on it are
// the real WebCrypto ones, and the shim holds the key by reference, so a key that came back
// extractable would come back extractable here too.

function installFakeIndexedDb(): Map<string, unknown> {
  const data = new Map<string, unknown>();
  const later = (fn: () => void) => queueMicrotask(fn);
  const store = {
    put: (v: unknown, k: string) => data.set(k, v),
    delete: (k: string) => data.delete(k),
    get: (k: string) => {
      const req: Record<string, unknown> = { result: data.get(k) };
      later(() => (req.onsuccess as (() => void) | undefined)?.());
      return req;
    },
  };
  const db = {
    transaction: () => {
      const tx: Record<string, unknown> = { objectStore: () => store };
      later(() => (tx.oncomplete as (() => void) | undefined)?.());
      return tx;
    },
    close: () => {},
  };
  (globalThis as Record<string, unknown>).indexedDB = {
    open: () => {
      const req: Record<string, unknown> = { result: db };
      later(() => (req.onsuccess as (() => void) | undefined)?.());
      return req;
    },
  };
  return data;
}

async function extractablePrivateKey(): Promise<CryptoKey> {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
  return pair.privateKey;
}

let stored: Map<string, unknown>;

beforeEach(() => {
  stored = installFakeIndexedDb();
});

afterEach(() => {
  delete (globalThis as Record<string, unknown>).indexedDB;
});

describe("the account key survives a refresh without becoming exfiltratable", () => {
  it("stores a key whose bytes cannot be read back out, from one that could", async () => {
    const original = await extractablePrivateKey();
    expect(original.extractable).toBe(true);
    await expect(crypto.subtle.exportKey("pkcs8", original)).resolves.toBeInstanceOf(ArrayBuffer);

    await putAccountKey(original);
    const back = (await getAccountKey())!;

    expect(back.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("pkcs8", back)).rejects.toThrow();
  });

  it("still unwraps the vault DEK — non-extractable, not useless", async () => {
    const original = await extractablePrivateKey();
    const peer = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
    await putAccountKey(original);
    const back = (await getAccountKey())!;

    // The shape a caller uses to unwrap an envelope: ECDH against the sender's public key.
    const derive = (priv: CryptoKey, pub: CryptoKey) =>
      crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256);
    const viaStored = new Uint8Array(await derive(back, peer.publicKey));
    const viaOriginal = new Uint8Array(await derive(original, peer.publicKey));

    expect(viaStored.byteLength).toBe(32);
    expect([...viaStored]).toEqual([...viaOriginal]);
  });

  it("keeps the key under one id, so a second sign-in replaces rather than accumulates", async () => {
    await putAccountKey(await extractablePrivateKey());
    await putAccountKey(await extractablePrivateKey());
    expect(stored.size).toBe(1);
  });

  it("returns null before anything is stored, and after a sign-out clears it", async () => {
    expect(await getAccountKey()).toBeNull();

    await putAccountKey(await extractablePrivateKey());
    expect(await getAccountKey()).not.toBeNull();

    await clearAccountKey();
    expect(await getAccountKey()).toBeNull();
  });

  it("clearing when nothing is stored is not an error", async () => {
    await expect(clearAccountKey()).resolves.toBeUndefined();
  });
});
