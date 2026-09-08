// The passphrase→key derivation shared by every passphrase-encrypted blob in this monorepo.
//
// W72. Two envelope formats derive their key identically and independently: the QBO token vault
// (`EB1`, packages/qbo/crypto.ts) and the health-dash v1 vault plus its account KEKs (`HD1`,
// apps/health-dash-web/src/lib/crypto.ts). Same PBKDF2-SHA256, same 200_000 iterations, same
// AES-GCM-256, same 16-byte salt and 12-byte IV — written out twice, so a decision to raise the
// iteration count could be taken in one file and silently not the other. Only the derivation is
// shared here.
//
// WHAT IS DELIBERATELY NOT SHARED: the envelope. `EB1` and `HD1` keep their own magic bytes, their
// own version handling and their own framing, in their own modules. A unified envelope would make a
// QBO token blob a syntactically valid input to the vault reader, which is a confusion this
// separation prevents for free. If you are here to "finish the job" by merging the two files — that
// is the bug this comment exists to stop.
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
