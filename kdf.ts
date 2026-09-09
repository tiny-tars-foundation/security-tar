// The passphrase→key derivation shared by every passphrase-encrypted blob this package produces.
//
// This module derives a key from a passphrase and salt and stops there — it does not define an
// envelope format, version byte, or framing. A caller with its own envelope needs (see `crypto.ts`
// for this package's own HD1 format) keeps its magic bytes, version handling, and framing in its own
// module. A unified envelope would make one format's blob a syntactically valid input to another
// format's reader, which is a confusion this separation prevents for free. Sharing only the
// derivation, never the envelope, is the design, not an oversight to "fix" by merging.
//
// RUNTIME-AGNOSTIC BY CONSTRUCTION: this module imports nothing and touches no global. Callers run
// in Node, the browser, and Workers alike, so the `SubtleCrypto` instance is passed in rather than
// reached for globally. That also makes the parameters testable without a runtime shim.

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
 * PBKDF2-SHA256 → raw bits, for a derivation whose output is not itself a key — this package's own
 * server-verifiable auth hash (see `crypto.ts`'s `deriveAuthHash`). Separate entry point rather than a flag on `deriveAesKey`, because a
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
