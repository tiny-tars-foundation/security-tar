import type { BlobStore, BlobConditional, StoredBlob } from "../blob-store";

// Minimal structural type for the R2 binding — no @cloudflare/workers-types dependency, and
// trivially mockable in tests. An adopter's own Pages Function route should import R2Bucket/
// R2BlobStore from here instead of declaring its own copy.
export interface R2ObjectBody {
  body: ReadableStream;
  /** The version token. Handed to the browser on GET and sent back as If-Match on PUT. */
  etag: string;
}
/** A precondition on a write. Verify this against real `workerd` in an adopter's own test suite — see ARCHITECTURE.md's "Adapters" section. */
export interface R2Conditional {
  etagMatches?: string;
  etagDoesNotMatch?: string;
}
export interface R2Bucket {
  get(key: string): Promise<R2ObjectBody | null>;
  /**
   * Returns the stored object (carrying its NEW etag), or `null` when an `onlyIf` precondition fails.
   * Null-on-failure rather than a throw is observed behaviour, not an assumption — see
   * tests/unit/r2-conditional-put.test.ts, which pins it against workerd.
   */
  put(key: string, value: Uint8Array, options?: { onlyIf?: R2Conditional }): Promise<{ etag: string } | null>;
  delete(key: string): Promise<void>;
}

/** `BlobStore`'s conditional field names, mapped onto R2's own (`onlyIf.etagMatches`/`etagDoesNotMatch`). */
function toOnlyIf(conditional?: BlobConditional): R2Conditional | undefined {
  if (!conditional) return undefined;
  if (conditional.ifMatch) return { etagMatches: conditional.ifMatch };
  if (conditional.ifNoneMatch === "*") return { etagDoesNotMatch: "*" };
  return undefined;
}

export class R2BlobStore implements BlobStore {
  constructor(private bucket: R2Bucket) {}

  async get(key: string): Promise<StoredBlob | null> {
    return this.bucket.get(key);
  }

  async put(key: string, value: Uint8Array, conditional?: BlobConditional): Promise<{ etag: string } | null> {
    const onlyIf = toOnlyIf(conditional);
    return onlyIf ? this.bucket.put(key, value, { onlyIf }) : this.bucket.put(key, value);
  }

  async delete(key: string): Promise<void> {
    await this.bucket.delete(key);
  }
}
