// A BlobStore persists an opaque byte blob under a string key, with an optional optimistic-
// concurrency conditional on write. Server-side counterpart to vault-sink.ts's browser-side
// VaultSink — that one calls an HTTP endpoint from the browser; this one is the interface the
// endpoint's own handler stores through, so the handler need not assume any particular backend.
export interface StoredBlob {
  body: ReadableStream;
  /** The version token of the object as stored. Handed back on GET, sent back as `ifMatch` on PUT. */
  etag: string;
}

export interface BlobConditional {
  /** Only write if the current object's etag matches this value. */
  ifMatch?: string;
  /** Only write if no object currently exists at this key. `"*"` is the only supported value. */
  ifNoneMatch?: "*";
}

export interface BlobStore {
  get(key: string): Promise<StoredBlob | null>;
  /**
   * Returns the written object's new etag, or `null` when a conditional fails. Null-on-failure
   * rather than a thrown error mirrors R2's own observed contract (see adapters/r2.ts) — an
   * implementation is a drop-in replacement only if it fails the same way.
   */
  put(key: string, value: Uint8Array, conditional?: BlobConditional): Promise<{ etag: string } | null>;
  delete(key: string): Promise<void>;
}
