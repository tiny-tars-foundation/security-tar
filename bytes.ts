/**
 * The one rule for handing a `Uint8Array` to WebCrypto.
 *
 * `subtle.*` takes a `BufferSource`, and a `Uint8Array` is only interchangeable with its underlying
 * `ArrayBuffer` when it spans the whole thing. A view produced by `slice()` on a larger buffer, or by
 * `subarray()`, carries a non-zero `byteOffset` — passing `view.buffer` there silently encrypts or
 * hashes the WRONG BYTES rather than failing. Every call site that used to write
 * `as unknown as ArrayBuffer` was one refactor away from that.
 *
 * The whole-buffer case returns the live buffer rather than a copy: the result is consumed
 * synchronously by the `subtle` call it is written for, so there is no window in which aliasing is
 * observable, and the copy would be on every vault read.
 */
export function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  return view.byteOffset === 0 && view.byteLength === view.buffer.byteLength
    ? (view.buffer as ArrayBuffer)
    : (view.slice().buffer as ArrayBuffer);
}
