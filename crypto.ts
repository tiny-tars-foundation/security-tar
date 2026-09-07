import { toArrayBuffer as toAB } from "./bytes";
import { deriveAesKey, deriveBits, IV_LEN, SALT_LEN } from "./kdf";

// HD1 is this app's own envelope and stays here. Only the derivation is shared with the QBO vault's
// EB1 — see the header of @tars/security/kdf for why the two formats must NOT be merged.
const MAGIC = new Uint8Array([0x48, 0x44, 0x31]); // "HD1"
const VERSION = 1;

const subtle = (globalThis.crypto as Crypto).subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

const deriveKey = (passphrase: string, salt: Uint8Array) => deriveAesKey(subtle, passphrase, salt);

// Deterministic, non-reversible bearer derived from the passphrase: base64url(SHA-256).
//
// No longer called from the browser: it gated /api/chat and /api/raw via CHAT_TOKEN/RAW_TOKEN
// until those routes moved to requireSession, and both secrets were deleted 2026-08-26. It is
// still the generator for the one bearer allowlist that survives — scripts/chat-allowlist.ts
// prints the VAULT_TOKEN value, which vault/[id].ts:73,155 checks and scripts/vault-sync.ts sends.
export async function deriveBearerToken(passphrase: string): Promise<string> {
  const digest = new Uint8Array(await subtle.digest("SHA-256", toAB(enc.encode(passphrase))));
  let bin = "";
  for (const b of digest) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function encryptVault<T = Record<string, unknown>>(data: T, passphrase: string): Promise<Uint8Array> {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(passphrase, salt);
  const plaintext = enc.encode(JSON.stringify(data));
  const ciphertext = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv: toAB(iv) }, key, toAB(plaintext)),
  );
  const out = new Uint8Array(MAGIC.length + 1 + SALT_LEN + IV_LEN + ciphertext.length);
  let o = 0;
  out.set(MAGIC, o); o += MAGIC.length;
  out[o++] = VERSION;
  out.set(salt, o); o += SALT_LEN;
  out.set(iv, o); o += IV_LEN;
  out.set(ciphertext, o);
  return out;
}

export async function decryptVault<T = Record<string, unknown>>(blob: Uint8Array, passphrase: string): Promise<T> {
  if (blob.length < MAGIC.length + 1 + SALT_LEN + IV_LEN) {
    throw new Error("blob too short");
  }
  for (let i = 0; i < MAGIC.length; i++) {
    if (blob[i] !== MAGIC[i]) throw new Error("not an HD1 blob");
  }
  let o = MAGIC.length;
  const version = blob[o++];
  if (version === VERSION_V2) throw new Error("v2 envelope blob: open it with decryptVaultV2 and a DEK");
  if (version !== VERSION) throw new Error(`unsupported version ${version}`);
  const salt = blob.slice(o, o + SALT_LEN); o += SALT_LEN;
  const iv = blob.slice(o, o + IV_LEN); o += IV_LEN;
  const ciphertext = blob.slice(o);
  const key = await deriveKey(passphrase, salt);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await subtle.decrypt({ name: "AES-GCM", iv: toAB(iv) }, key, toAB(ciphertext));
  } catch {
    throw new Error("wrong passphrase or corrupt blob");
  }
  return JSON.parse(dec.decode(plaintext)) as T;
}

// ── W44 envelope encryption (v2) ─────────────────────────────────────────────
// v1 above (passphrase → PBKDF2 → AES key → blob) is untouched. v2 splits the key:
// a random per-vault DEK encrypts the blob, and the DEK is wrapped per principal
// (owner, provider, support) to their ECDH public key. The passphrase path is gone;
// a v2 blob is opened only with its DEK. This is what makes "grant access" a
// re-wrap of the DEK rather than a shared secret.

const VERSION_V2 = 2;
const KEYID_LEN = 16; // opaque per-vault key id, reserved for future re-key tracking
const EC_PARAMS = { name: "ECDH", namedCurve: "P-256" } as const;

export interface AccountKeypair {
  publicKeyJwk: JsonWebKey;
  privateKey: CryptoKey; // extractable ECDH private — wrap it immediately, then drop the handle
}

export interface DEKEnvelope {
  wrappedDEK: Uint8Array; // iv(12) + AES-GCM(sharedKey, raw DEK)
  ephemeralPublicKeyJwk: JsonWebKey;
}

export async function generateAccountKeypair(): Promise<AccountKeypair> {
  const pair = await subtle.generateKey(EC_PARAMS, true, ["deriveKey", "deriveBits"]);
  const publicKeyJwk = await subtle.exportKey("jwk", pair.publicKey);
  return { publicKeyJwk, privateKey: pair.privateKey };
}

// A KEK wraps the account's private key. Password → PBKDF2 (same params as v1);
// passkey → the WebAuthn PRF secret imported directly as an AES-GCM key.
export async function deriveKekFromPassword(password: string, salt: Uint8Array): Promise<CryptoKey> {
  return deriveKey(password, salt);
}

export async function kekFromPrfSecret(prfBytes: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", toAB(prfBytes), "AES-GCM", false, ["encrypt", "decrypt"]);
}

// Server-verifiable password auth signal, in a DISTINCT KDF domain from the KEK (salt||"|auth"),
// so it can be sent to the server without leaking the key-wrapping secret. The server stores
// SHA-256(authHash) and compares — it never sees the password or the KEK. base64url of 256 bits.
export async function deriveAuthHash(password: string, salt: Uint8Array): Promise<string> {
  const suffix = enc.encode("|auth");
  const domainSalt = new Uint8Array(salt.length + suffix.length);
  domainSalt.set(salt, 0);
  domainSalt.set(suffix, salt.length);
  const bits = await deriveBits(subtle, password, domainSalt);
  let bin = "";
  for (const b of bits) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Wrap/unwrap the account private key under a KEK: AES-GCM over its PKCS8 bytes. Blob = iv(12)+ct.
export async function wrapPrivateKey(privateKey: CryptoKey, kek: CryptoKey): Promise<Uint8Array> {
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", privateKey));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: toAB(iv) }, kek, toAB(pkcs8)));
  const out = new Uint8Array(IV_LEN + ct.length);
  out.set(iv, 0);
  out.set(ct, IV_LEN);
  return out;
}

export async function unwrapPrivateKey(blob: Uint8Array, kek: CryptoKey): Promise<CryptoKey> {
  const iv = blob.slice(0, IV_LEN);
  const ct = blob.slice(IV_LEN);
  let pkcs8: ArrayBuffer;
  try {
    pkcs8 = await subtle.decrypt({ name: "AES-GCM", iv: toAB(iv) }, kek, toAB(ct));
  } catch {
    throw new Error("cannot unwrap private key (wrong KEK or corrupt blob)");
  }
  // Extractable so an authorized holder can RE-WRAP it — needed to add a login method or regenerate the
  // recovery code (W44 P8/P8b), which wrap this same key under a new KEK. Same rationale/posture as the
  // DEK returned by unwrapDEKWithPrivateKey (also extractable for re-granting). The key stays in-memory
  // only, same trust boundary as the session's DEK.
  return subtle.importKey("pkcs8", pkcs8, EC_PARAMS, true, ["deriveKey", "deriveBits"]);
}

// Import a raw PKCS8 ECDH private key (extractable, so it can be re-wrapped to add a login method —
// same trust boundary as unwrapPrivateKey's output). W45: the Google path moves the plaintext key
// over the wire (server-custody), so both server (re-wrap under the server KEK) and client (recover
// the DEK) import it here instead of unwrapping a KEK-wrapped blob.
export async function importPrivateKeyPkcs8(pkcs8: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("pkcs8", toAB(pkcs8), EC_PARAMS, true, ["deriveKey", "deriveBits"]);
}

export async function generateDEK(): Promise<CryptoKey> {
  return subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

// ECDH-ES: wrap the DEK to a recipient public key via an ephemeral ECDH → AES-GCM key.
// (A256GCM over the raw DEK; equivalent to JWE ECDH-ES+A256GCM — simpler and less
// error-prone here than AES-KW, which the plan named illustratively.)
export async function wrapDEKForPublicKey(dek: CryptoKey, recipientPublicKeyJwk: JsonWebKey): Promise<DEKEnvelope> {
  const recipientPub = await subtle.importKey("jwk", recipientPublicKeyJwk, EC_PARAMS, false, []);
  const eph = await subtle.generateKey(EC_PARAMS, true, ["deriveKey"]);
  const shared = await subtle.deriveKey(
    { name: "ECDH", public: recipientPub },
    eph.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const rawDek = new Uint8Array(await subtle.exportKey("raw", dek));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: toAB(iv) }, shared, toAB(rawDek)));
  const wrappedDEK = new Uint8Array(IV_LEN + ct.length);
  wrappedDEK.set(iv, 0);
  wrappedDEK.set(ct, IV_LEN);
  return { wrappedDEK, ephemeralPublicKeyJwk: await subtle.exportKey("jwk", eph.publicKey) };
}

export async function unwrapDEKWithPrivateKey(
  wrappedDEK: Uint8Array,
  ephemeralPublicKeyJwk: JsonWebKey,
  privateKey: CryptoKey,
): Promise<CryptoKey> {
  const ephPub = await subtle.importKey("jwk", ephemeralPublicKeyJwk, EC_PARAMS, false, []);
  const shared = await subtle.deriveKey(
    { name: "ECDH", public: ephPub },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const iv = wrappedDEK.slice(0, IV_LEN);
  const ct = wrappedDEK.slice(IV_LEN);
  let raw: ArrayBuffer;
  try {
    raw = await subtle.decrypt({ name: "AES-GCM", iv: toAB(iv) }, shared, toAB(ct));
  } catch {
    throw new Error("cannot unwrap DEK (wrong key or corrupt envelope)");
  }
  // extractable so an authorized holder can re-wrap it to grant another principal
  return subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

// W73 — the DEK wrapped under a KEK, for a provider-issued recovery grant.
//
// The raw-key twin of wrapPrivateKey/unwrapPrivateKey above: same AES-GCM, same iv‖ct blob shape, same
// reasoning. It exists because a recovery grant hands the DEK to a one-time code rather than to a
// principal's public key — the ECDH envelope path needs a keypair, and a code read down a phone line
// is not one.
//
// The DEK is `extractable` by design (see unwrapDEKWithPrivateKey below), which is what makes
// exportKey("raw") here possible at all.
export async function wrapDEKWithKek(dek: CryptoKey, kek: CryptoKey): Promise<Uint8Array> {
  const raw = new Uint8Array(await subtle.exportKey("raw", dek));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: toAB(iv) }, kek, toAB(raw)));
  const out = new Uint8Array(IV_LEN + ct.length);
  out.set(iv, 0);
  out.set(ct, IV_LEN);
  return out;
}

export async function unwrapDEKWithKek(blob: Uint8Array, kek: CryptoKey): Promise<CryptoKey> {
  const iv = blob.slice(0, IV_LEN);
  const ct = blob.slice(IV_LEN);
  let raw: ArrayBuffer;
  try {
    raw = await subtle.decrypt({ name: "AES-GCM", iv: toAB(iv) }, kek, toAB(ct));
  } catch {
    // AES-GCM's tag is what tells a holder of this blob that a guessed code was right, which is why the
    // blob is deleted the moment its grant is consumed — see migrations/0009.
    throw new Error("cannot unwrap DEK (wrong recovery code or corrupt grant)");
  }
  // Extractable for the same reason as every other DEK here: the recovering client immediately re-wraps
  // it to the new account key it just generated.
  return subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

// HD1 v2 blob: magic(3) + version=2(1) + vaultKeyId(16) + iv(12) + AES-GCM(DEK, JSON).
// Header = 32 B, equal to v1, so the Functions' MIN_BYTES=32 + magic checks stay valid.
export async function encryptVaultV2<T = Record<string, unknown>>(data: T, dek: CryptoKey): Promise<Uint8Array> {
  const vaultKeyId = globalThis.crypto.getRandomValues(new Uint8Array(KEYID_LEN));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const plaintext = enc.encode(JSON.stringify(data));
  const ciphertext = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: toAB(iv) }, dek, toAB(plaintext)));
  const out = new Uint8Array(MAGIC.length + 1 + KEYID_LEN + IV_LEN + ciphertext.length);
  let o = 0;
  out.set(MAGIC, o); o += MAGIC.length;
  out[o++] = VERSION_V2;
  out.set(vaultKeyId, o); o += KEYID_LEN;
  out.set(iv, o); o += IV_LEN;
  out.set(ciphertext, o);
  return out;
}

export async function decryptVaultV2<T = Record<string, unknown>>(blob: Uint8Array, dek: CryptoKey): Promise<T> {
  const header = MAGIC.length + 1 + KEYID_LEN + IV_LEN;
  if (blob.length < header) throw new Error("blob too short");
  for (let i = 0; i < MAGIC.length; i++) if (blob[i] !== MAGIC[i]) throw new Error("not an HD1 blob");
  let o = MAGIC.length;
  const version = blob[o++];
  if (version !== VERSION_V2) throw new Error(`expected HD1 v2, got version ${version}`);
  o += KEYID_LEN; // vaultKeyId — reserved/opaque
  const iv = blob.slice(o, o + IV_LEN); o += IV_LEN;
  const ciphertext = blob.slice(o);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await subtle.decrypt({ name: "AES-GCM", iv: toAB(iv) }, dek, toAB(ciphertext));
  } catch {
    throw new Error("wrong DEK or corrupt blob");
  }
  return JSON.parse(dec.decode(plaintext)) as T;
}
