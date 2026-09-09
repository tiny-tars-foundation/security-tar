import { describe, it, expect } from "vitest";
import { R2BlobStore, type R2Bucket, type R2Conditional } from "../adapters/r2";

// R2BlobStore is a thin conditional-mapping shim (BlobConditional -> R2's onlyIf shape). No
// workerd/Miniflare dependency here by design (see package.json's devDependencies) — this pins the
// mapping logic against a hand-written fake bucket instead. The real conditional-write semantics
// (etagMatches/etagDoesNotMatch actually enforced) are only proven against real workerd, in an
// adopter's own test suite — see ARCHITECTURE.md's "Adapters" section.

function fakeBucket() {
  const store = new Map<string, Uint8Array>();
  const etags = new Map<string, string>();
  let seq = 0;
  const calls: { key: string; options?: { onlyIf?: R2Conditional } }[] = [];

  const bucket: R2Bucket = {
    async get(key) {
      if (!store.has(key)) return null;
      const value = store.get(key)!;
      return { body: new Response(value as unknown as BodyInit).body!, etag: etags.get(key)! };
    },
    async put(key, value, options) {
      calls.push({ key, options });
      const current = etags.get(key);
      const onlyIf = options?.onlyIf;
      if (onlyIf?.etagMatches !== undefined && onlyIf.etagMatches !== current) return null;
      if (onlyIf?.etagDoesNotMatch === "*" && current !== undefined) return null;
      store.set(key, value);
      const etag = `etag-${++seq}`;
      etags.set(key, etag);
      return { etag };
    },
    async delete(key) {
      store.delete(key);
      etags.delete(key);
    },
  };

  return { bucket, store, calls };
}

describe("R2BlobStore", () => {
  it("passes puts through with no conditional when none is given", async () => {
    const { bucket, calls } = fakeBucket();
    const blobStore = new R2BlobStore(bucket);

    const result = await blobStore.put("k", new Uint8Array([1, 2, 3]));

    expect(result?.etag).toBeTruthy();
    expect(calls[0].options).toBeUndefined();
  });

  it("maps ifMatch onto R2's onlyIf.etagMatches", async () => {
    const { bucket, calls } = fakeBucket();
    const blobStore = new R2BlobStore(bucket);
    const created = await blobStore.put("k", new Uint8Array([1]));

    const result = await blobStore.put("k", new Uint8Array([2]), { ifMatch: created!.etag });

    expect(result?.etag).toBeTruthy();
    expect(calls[1].options?.onlyIf).toEqual({ etagMatches: created!.etag });
  });

  it("maps ifNoneMatch: '*' onto R2's onlyIf.etagDoesNotMatch", async () => {
    const { bucket, calls } = fakeBucket();
    const blobStore = new R2BlobStore(bucket);

    const result = await blobStore.put("k", new Uint8Array([1]), { ifNoneMatch: "*" });

    expect(result?.etag).toBeTruthy();
    expect(calls[0].options?.onlyIf).toEqual({ etagDoesNotMatch: "*" });
  });

  it("returns null, not a throw, when a conditional fails — mirrors R2's own contract", async () => {
    const { bucket } = fakeBucket();
    const blobStore = new R2BlobStore(bucket);
    await blobStore.put("k", new Uint8Array([1]));

    const stale = await blobStore.put("k", new Uint8Array([2]), { ifMatch: "wrong-etag" });
    const clobber = await blobStore.put("k", new Uint8Array([3]), { ifNoneMatch: "*" });

    expect(stale).toBeNull();
    expect(clobber).toBeNull();
  });

  it("get/delete pass straight through to the bucket", async () => {
    const { bucket, store } = fakeBucket();
    const blobStore = new R2BlobStore(bucket);
    await blobStore.put("k", new Uint8Array([9, 9]));

    expect(await blobStore.get("k")).not.toBeNull();
    expect(await blobStore.get("missing")).toBeNull();

    await blobStore.delete("k");
    expect(store.has("k")).toBe(false);
  });
});
