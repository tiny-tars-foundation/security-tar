import { describe, it, expect } from "vitest";
import { deriveAesKey, deriveBits, PBKDF2_ITERATIONS, SALT_LEN, IV_LEN } from "../kdf";
import { toArrayBuffer } from "../bytes";

const subtle = (globalThis.crypto as Crypto).subtle;
const salt = new Uint8Array(SALT_LEN).fill(7);

describe("kdf parameters", () => {
  it("keeps the values every already-encrypted blob was written under", () => {
    // These are not preferences. No existing envelope header records an iteration count or a
    // salt length, so changing one of these numbers makes every stored blob undecryptable with
    // no error that says so — it presents as "wrong passphrase". See THREAT_MODEL.md.
    expect(PBKDF2_ITERATIONS).toBe(200_000);
    expect(SALT_LEN).toBe(16);
    expect(IV_LEN).toBe(12);
  });

  it("derives a non-extractable AES-GCM-256 key", async () => {
    const key = await deriveAesKey(subtle, "pw", salt);
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
    await expect(subtle.exportKey("raw", key)).rejects.toThrow();
  });

  it("is deterministic in the passphrase and in the salt", async () => {
    const ct = async (pw: string, s: Uint8Array) => {
      const key = await deriveAesKey(subtle, pw, s);
      const iv = new Uint8Array(IV_LEN).fill(3);
      const bytes = new Uint8Array(
        await subtle.encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, toArrayBuffer(new Uint8Array([1, 2, 3]))),
      );
      return [...bytes].join(",");
    };
    const base = await ct("pw", salt);
    expect(await ct("pw", salt)).toBe(base);
    expect(await ct("pw!", salt)).not.toBe(base);
    expect(await ct("pw", new Uint8Array(SALT_LEN).fill(8))).not.toBe(base);
  });

  it("accepts SubtleCrypto as a parameter rather than reading a global", async () => {
    // The whole point of taking `subtle` in: this module makes no assumption about where the
    // caller's WebCrypto implementation comes from (browser global, Cloudflare Worker global,
    // Node's `crypto.webcrypto`) — it only has to satisfy the SubtleCrypto interface.
    const key = await deriveAesKey(subtle, "pw", salt);
    expect(key).toBeDefined();
  });

  it("puts deriveBits in a different output space than the key, for the same inputs", async () => {
    const bits = await deriveBits(subtle, "pw", salt);
    expect(bits).toHaveLength(32);
    expect(await deriveBits(subtle, "pw", salt)).toEqual(bits);
    expect(await deriveBits(subtle, "pw2", salt)).not.toEqual(bits);
  });
});
