// The passphrase→key derivation shared by every passphrase-encrypted blob that builds on this
// package.
//
// This derivation is deliberately factored out on its own, separate from any particular envelope
// format: PBKDF2-SHA256, 200_000 iterations, AES-GCM-256, a 16-byte salt and a 12-byte IV. An
// adopter building a second, unrelated encrypted-blob format alongside this package's own HD1
// envelope (`crypto.ts`) should reuse this file rather than reimplementing the derivation —
// reimplementing it independently is exactly how a later decision to raise the iteration count
// gets taken in one copy and silently not the other.
//
// WHAT IS DELIBERATELY NOT SHARED: the envelope. HD1 keeps its own magic bytes, its own version
// handling and its own framing in its own module — a sibling format should do the same in its own.
// A unified envelope would make a foreign blob a syntactically valid input to this package's vault
// reader, which is a confusion this separation prevents for free. If you are here to "finish the
// job" by merging formats — that is the bug this comment exists to stop.
//
// RUNTIME-AGNOSTIC BY CONSTRUCTION: this module imports nothing and touches no global. One caller is
// Node-only (`node:crypto`'s webcrypto), the others run in the browser and in Workers, so the
// `SubtleCrypto` is passed in rather than reached for. That also makes the parameters testable
// without a runtime shim.

import { toArrayBuffer } from "./bytes";

/**
 * OWASP's floor for PBKDF2-SHA256 at the time this was set. Raising it is a compatibility decision,
 * not a tuning knob: existing blobs carry no iteration count in their header, so both formats would
 * have to grow a version byte that records it before this number can move.
 */
export const PBKDF2_ITERATIONS = 200_000;
export const SALT_LEN = 16;
/** AES-GCM standard nonce length. Not 16 — a non-96-bit IV is re-hashed by GHASH and buys nothing. */
export const IV_LEN = 12;

const enc = new TextEncoder();

/**
 * PBKDF2-SHA256 over `passphrase` and `salt` → a non-extractable AES-GCM-256 key.
 *
 * Non-extractable is the point: the caller gets something it can encrypt and decrypt with and cannot
 * export, so a derived key cannot escape the module that derived it.
 */
export async function deriveAesKey(
  subtle: SubtleCrypto,
  passphrase: string,
  salt: Uint8Array,
  usages: KeyUsage[] = ["encrypt", "decrypt"],
): Promise<CryptoKey> {
  const baseKey = await subtle.importKey("raw", toArrayBuffer(enc.encode(passphrase)), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", salt: toArrayBuffer(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

/**
 * PBKDF2-SHA256 → raw bits, for a derivation whose output is not itself a key — health-dash's
 * server-verifiable auth hash. Separate entry point rather than a flag on `deriveAesKey`, because a
 * function that sometimes returns exportable bytes and sometimes an unexportable key is exactly the
 * kind of thing a reviewer has to read twice.
 */
export async function deriveBits(
  subtle: SubtleCrypto,
  passphrase: string,
  salt: Uint8Array,
  length = 256,
): Promise<Uint8Array> {
  const baseKey = await subtle.importKey("raw", toArrayBuffer(enc.encode(passphrase)), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(
    await subtle.deriveBits({ name: "PBKDF2", salt: toArrayBuffer(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, baseKey, length),
  );
}
