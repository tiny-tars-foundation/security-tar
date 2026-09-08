// Structural D1 types only, so this module has no dependency on @cloudflare/workers-types — any
// D1-compatible database (Cloudflare's own, or a test double) satisfies this by shape.

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  /**
   * D1 runs a batch as a single implicit transaction, which `vault.ts`'s `replaceEnvelopes`/
   * `commitRotation` need and nothing else here does. The shape is pinned against real workerd by
   * the adopting app's own tests rather than trusted from a comment.
   */
  batch(statements: D1PreparedStatement[]): Promise<unknown[]>;
}
export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = unknown>(): Promise<T | null>;
  all<T = unknown>(): Promise<{ results: T[] }>;
  run(): Promise<unknown>;
}

export function toBytes(blob: unknown): Uint8Array {
  return blob instanceof Uint8Array ? blob : new Uint8Array(blob as ArrayBuffer);
}
