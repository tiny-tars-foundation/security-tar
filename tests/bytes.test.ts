import { describe, it, expect } from "vitest";
import { toArrayBuffer } from "../bytes";

describe("toArrayBuffer", () => {
  it("returns the exact bytes of a view spanning its whole buffer", () => {
    const view = new Uint8Array([1, 2, 3, 4]);
    expect([...new Uint8Array(toArrayBuffer(view))]).toEqual([1, 2, 3, 4]);
  });

  it("does not silently include neighboring bytes for a subarray with a non-zero byteOffset", () => {
    // A Uint8Array produced by .subarray() shares the underlying buffer with whatever it was cut
    // from — view.buffer is the WHOLE original buffer, not just the slice. Passing view.buffer
    // straight to SubtleCrypto would operate on the wrong bytes without ever throwing. This is
    // the regression this helper exists to prevent.
    const backing = new Uint8Array([9, 9, 1, 2, 3, 4, 9, 9]);
    const view = backing.subarray(2, 6);
    expect(view.byteOffset).toBe(2);
    expect([...new Uint8Array(toArrayBuffer(view))]).toEqual([1, 2, 3, 4]);
  });

  it("returns a buffer whose length matches the view, not the backing buffer", () => {
    const backing = new Uint8Array(16);
    const view = backing.subarray(4, 8);
    expect(toArrayBuffer(view).byteLength).toBe(4);
  });
});
