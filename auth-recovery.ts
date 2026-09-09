import {
  generateAccountKeypair,
  deriveKekFromPassword,
  deriveAuthHash,
  wrapPrivateKey,
  unwrapPrivateKey,
  wrapDEKWithKek,
  unwrapDEKWithKek,
  wrapDEKForPublicKey,
  unwrapDEKWithPrivateKey,
} from "./crypto";
import { bytesToBase64, base64ToBytes, bytesToHex, hexToBytes, rand, failed, KDF_ITERATIONS, currentAuthHashFor } from "./auth-client";

// Not a security boundary (the recovery KEK is still PBKDF2-derived from this code) —
// just a printable code the user can write down. Excludes ambiguous chars (0/O, 1/I).
const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function randomRecoveryCode(): string {
  return Array.from(rand(20), (b) => RECOVERY_ALPHABET[b % RECOVERY_ALPHABET.length]).join("");
}

// Account settings: change email/display name; add/remove a login method (password/passkey).
// Adding a method re-wraps the account's in-memory private key under the new method's KEK — same
// zero-knowledge model as signup; the server never sees the key.

export interface LoginMethod {
  method: "password" | "passkey" | "google" | "recovery";
  createdAt: string;
  isRecovery: boolean;
}

export async function listMethods(): Promise<LoginMethod[]> {
  const res = await fetch("/api/account/methods", { cache: "no-store" });
  if (!res.ok) throw await failed(res, "list methods failed");
  return ((await res.json()) as { methods: LoginMethod[] }).methods;
}

export async function updateProfile(updates: { email?: string; displayName?: string; unitSystem?: "metric" | "imperial" }): Promise<void> {
  const res = await fetch("/api/account", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(updates) });
  if (!res.ok) throw await failed(res, "profile update failed");
}

export async function removeMethod(method: "password" | "passkey" | "google"): Promise<void> {
  const res = await fetch("/api/account/methods", { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ method }) });
  if (!res.ok) throw await failed(res, "remove method failed");
}

/**
 * Sets or replaces the account password.
 *
 * `currentPassword` is the step-up proof, and is REQUIRED by the server whenever a password
 * already exists. It is derived against the account's CURRENT salt, fetched by email, because an
 * authHash is only meaningful paired with the salt it was derived from; deriving the proof against
 * the new salt would produce a value that matches nothing.
 *
 * Undefined is correct for an account setting its first password — a passkey-only or Google-only
 * account has nothing to prove and nothing is being destroyed.
 */
export async function addPasswordMethod(
  privateKey: CryptoKey,
  newPassword: string,
  currentPassword?: string,
  email?: string,
): Promise<void> {
  const currentAuthHash = await currentAuthHashFor(email, currentPassword);

  const salt = rand(16);
  const kek = await deriveKekFromPassword(newPassword, salt);
  const wrappedPrivateKey = await wrapPrivateKey(privateKey, kek);
  const authHash = await deriveAuthHash(newPassword, salt);
  const res = await fetch("/api/account/methods", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      method: "password",
      wrappedPrivateKey: bytesToBase64(wrappedPrivateKey),
      kdfParams: { salt: bytesToHex(salt), iterations: KDF_ITERATIONS },
      authHash,
      ...(currentAuthHash ? { currentAuthHash } : {}),
    }),
  });
  if (res.status === 401) {
    const { error } = (await res.json().catch(() => ({ error: "" }))) as { error?: string };
    throw new Error(error || "enter your current password to set a new one");
  }
  if (!res.ok) throw await failed(res, "add password failed");
}

// Recover with a recovery code (mirrors loginPassword, keyed on the recovery credential).
// Returns the same shape as loginPassword so it flows straight into the app's enter-account path.
export async function recoverAccount(
  email: string,
  recoveryCode: string,
  /**
   * The replacement password, set as part of redeeming the code.
   *
   * Without this the flow was a trap: redeeming signed you in but left the forgotten password in place,
   * so the next sign-in put you right back where you started. It cannot be a follow-up call to
   * `/api/account/methods` either — the account still holds its old password credential, so the
   * add-a-method step-up would demand the very password being recovered.
   *
   * So the code is redeemed TWICE against the same endpoint: once to obtain the wrapped key (which is
   * the only way to get it — the server releases it on proof, never on request), and once to install
   * the re-wrapped key. The second call re-proves the recovery code, so the replacement is authorised
   * by the code rather than by the session the first call happened to mint.
   */
  newPassword?: string,
): Promise<{ accountId: string; vaultId: string | null; r2Key: string | null; privateKey: CryptoKey; dek: CryptoKey | null; rotationPending: boolean }> {
  const saltRes = await fetch(`/api/auth/recovery/salt?email=${encodeURIComponent(email)}`);
  // Same as the password path above: a decoy is returned for an address with no recovery credential,
  // so a non-200 is a fault, not an answer about the account.
  if (!saltRes.ok) throw new Error(`recovery is unavailable right now (${saltRes.status})`);
  const { salt } = (await saltRes.json()) as { salt: string; iterations: number };

  const recoveryAuthHash = await deriveAuthHash(recoveryCode, hexToBytes(salt));
  const res = await fetch("/api/auth/recovery/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, recoveryAuthHash }),
  });
  if (!res.ok) throw new Error(`recovery failed: ${res.status}`);
  const data = (await res.json()) as {
    accountId: string;
    vaultId: string | null;
    r2Key: string | null;
    wrappedPrivateKey: string;
    kdfParams: { salt: string; iterations: number };
    ownerEnvelope: { wrappedDEK: string; ephemeralPublicKeyJwk: JsonWebKey } | null;
  };

  const kek = await deriveKekFromPassword(recoveryCode, hexToBytes(data.kdfParams.salt));
  const privateKey = await unwrapPrivateKey(base64ToBytes(data.wrappedPrivateKey), kek);
  const dek = data.ownerEnvelope
    ? await unwrapDEKWithPrivateKey(base64ToBytes(data.ownerEnvelope.wrappedDEK), data.ownerEnvelope.ephemeralPublicKeyJwk, privateKey)
    : null;

  if (newPassword) {
    // The SAME private key, re-wrapped under a KEK derived from the new password. It is not a new
    // keypair, which is why the account's passkey and Google credentials keep working afterwards.
    const newSalt = rand(16);
    const newKek = await deriveKekFromPassword(newPassword, newSalt);
    const install = await fetch("/api/auth/recovery/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email,
        recoveryAuthHash,
        newCredential: {
          wrappedPrivateKey: bytesToBase64(await wrapPrivateKey(privateKey, newKek)),
          kdfParams: { salt: bytesToHex(newSalt), iterations: KDF_ITERATIONS },
          authHash: await deriveAuthHash(newPassword, newSalt),
        },
      }),
    });
    // Deliberately loud rather than silent: the caller is already signed in at this point, so a
    // swallowed failure would leave the user believing they had set a password they had not.
    if (!install.ok) throw new Error(`your code was accepted but the new password could not be saved (${install.status}) — try setting it from Account settings`);
  }

  return { accountId: data.accountId, vaultId: data.vaultId, r2Key: data.r2Key, privateKey, dek, rotationPending: (data as { rotationPending?: boolean }).rotationPending ?? false };
}

// Regenerate the recovery code (owner session): re-wrap the in-memory private key under a fresh code +
// store the verifier. Returns the new code to display once.
// ── Provider-issued recovery ──────────────────────────────────────────────────
// Apple's recovery-contact model: a clinician who already holds the patient's DEK re-wraps it under a
// one-time code and READS THE CODE TO THEM. It is never emailed — see RECOVERY.md I2; the server would
// have to be given the code, and it already holds the wrapped DEK.

// Crockford base32, minus the characters that are misheard or mistyped (I/L/O/U). 12 characters ≈ 60
// bits, which is only safe because the server caps attempts and expires the grant in an hour — a code
// short enough to read down a phone line cannot also resist an unbounded oracle.
const GRANT_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export function randomGrantCode(): string {
  const raw = Array.from(rand(12), (b) => GRANT_ALPHABET[b % GRANT_ALPHABET.length]).join("");
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8)}`;
}

/** Strips the display grouping so "a7k2-9qmf-3xpb" and "A7K29QMF3XPB" are the same code. */
export function normalizeGrantCode(input: string): string {
  return input.replace(/[^0-9A-Za-z]/g, "").toUpperCase();
}

/**
 * Which ladder rung a pasted/typed string belongs to, by shape alone. `randomRecoveryCode`
 * always emits 20 raw characters; `randomGrantCode` always emits 12 (displayed grouped). No
 * collision is possible by construction, so the stripped length alone is enough to route —
 * this never has to look at what the string actually contains.
 */
export function detectRecoveryKind(raw: string): "code" | "grant" {
  return normalizeGrantCode(raw).length === 12 ? "grant" : "code";
}

/**
 * Clinician side. Unwraps the patient's DEK with the clinician's own key — which is what provider
 * access already is — and re-wraps it under the code. Returns the code to display once.
 */
export async function issueRecoveryCode(
  patientAccountId: string,
  envelope: { wrappedDEK: string; ephemeralPublicKeyJwk: JsonWebKey },
  providerKey: CryptoKey,
): Promise<{ code: string; expiresAt: string }> {
  const code = randomGrantCode();
  const normalized = normalizeGrantCode(code);
  const dek = await unwrapDEKWithPrivateKey(base64ToBytes(envelope.wrappedDEK), envelope.ephemeralPublicKeyJwk, providerKey);
  const salt = rand(16);
  const res = await fetch("/api/recovery/grant", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      patientAccountId,
      wrappedDek: bytesToBase64(await wrapDEKWithKek(dek, await deriveKekFromPassword(normalized, salt))),
      kdfParams: { salt: bytesToHex(salt), iterations: KDF_ITERATIONS },
      codeAuthHash: await deriveAuthHash(normalized, salt),
    }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `could not issue a recovery code (${res.status})`);
  return { code, expiresAt: (await res.json()).expiresAt };
}

/**
 * Patient side. Two calls against the same endpoint: the first proves the code and returns the wrapped
 * DEK, the second installs a brand-new keypair locked under the new password. The code is proved on
 * both — the second is not authorised by the first having happened.
 *
 * Unlike `recoverAccount`, this MINTS A NEW KEYPAIR rather than re-wrapping the old one, because the
 * old private key is exactly what the patient no longer has. That is why the server clears the other
 * credentials: they wrap a key nothing references any more.
 */
export async function redeemRecoveryCode(
  email: string,
  code: string,
  newPassword: string,
): Promise<{ accountId: string; vaultId: string | null; r2Key: string | null; privateKey: CryptoKey; dek: CryptoKey; rotationPending: boolean }> {
  const normalized = normalizeGrantCode(code);
  const saltRes = await fetch(`/api/auth/recovery/grant-salt?email=${encodeURIComponent(email)}`);
  if (!saltRes.ok) throw new Error(`recovery is unavailable right now (${saltRes.status})`);
  const { salt } = (await saltRes.json()) as { salt: string };
  const codeAuthHash = await deriveAuthHash(normalized, hexToBytes(salt));

  const first = await fetch("/api/auth/recovery/grant-redeem", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, codeAuthHash }),
  });
  if (!first.ok) throw new Error((await first.json().catch(() => ({}))).error || "that code is not valid, or it has expired");
  const { wrappedDek } = (await first.json()) as { wrappedDek: string };
  const dek = await unwrapDEKWithKek(base64ToBytes(wrappedDek), await deriveKekFromPassword(normalized, hexToBytes(salt)));

  const fresh = await generateAccountKeypair();
  const pwSalt = rand(16);
  const envelope = await wrapDEKForPublicKey(dek, fresh.publicKeyJwk);
  const second = await fetch("/api/auth/recovery/grant-redeem", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email,
      codeAuthHash,
      newIdentity: {
        publicKeyJwk: fresh.publicKeyJwk,
        wrappedPrivateKey: bytesToBase64(await wrapPrivateKey(fresh.privateKey, await deriveKekFromPassword(newPassword, pwSalt))),
        kdfParams: { salt: bytesToHex(pwSalt), iterations: KDF_ITERATIONS },
        authHash: await deriveAuthHash(newPassword, pwSalt),
        envelope: { wrappedDEK: bytesToBase64(envelope.wrappedDEK), ephemeralPublicKeyJwk: envelope.ephemeralPublicKeyJwk },
      },
    }),
  });
  if (!second.ok) throw new Error((await second.json().catch(() => ({}))).error || `could not finish recovery (${second.status})`);
  const data = (await second.json()) as { accountId: string; vaultId: string | null; r2Key: string | null; rotationPending: boolean };
  return { ...data, privateKey: fresh.privateKey, dek };
}

// DEK rotation. Fetch the re-wrap targets (owner + org + active providers), then commit the
// new envelope set after the client re-encrypts the vault under a fresh DEK.
export interface VaultPrincipals {
  selfAccountId: string;
  orgAccountId: string;
  selfPublicKeyJwk: JsonWebKey;
  orgPublicKeyJwk: JsonWebKey;
  providers: { accountId: string; publicKeyJwk: JsonWebKey }[];
  envelopePrincipalIds: string[];
  orgRecoveryRevokedAt: string | null;
  vaultId: string;
}
export async function getVaultPrincipals(): Promise<VaultPrincipals> {
  const res = await fetch("/api/vault/principals", { cache: "no-store" });
  if (!res.ok) throw await failed(res, "principals failed");
  return res.json();
}
/**
 * Reserve the object the re-key will write to. The server mints the id; the caller PUTs the
 * blob re-encrypted under the new DEK there, then calls `rotateVault` to make the swap real.
 */
export async function stageVaultRotation(vaultId: string): Promise<string> {
  const res = await fetch("/api/vault/rotate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ phase: "stage", vaultId }),
  });
  if (!res.ok) throw await failed(res, "stage rotation failed");
  return (await res.json()).newVaultId as string;
}

export async function rotateVault(args: {
  vaultId: string;
  newVaultId: string;
  envelopes: { principalAccountId: string; wrappedDEK: string; ephemeralPublicKeyJwk: JsonWebKey }[];
}): Promise<void> {
  const res = await fetch("/api/vault/rotate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ phase: "commit", ...args }),
  });
  if (!res.ok) throw await failed(res, "rotate failed");
}

export async function regenerateRecoveryCode(privateKey: CryptoKey): Promise<string> {
  const recoveryCode = randomRecoveryCode();
  const salt = rand(16);
  const kek = await deriveKekFromPassword(recoveryCode, salt);
  const wrappedPrivateKey = await wrapPrivateKey(privateKey, kek);
  const recoveryAuthHash = await deriveAuthHash(recoveryCode, salt);
  const res = await fetch("/api/account/recovery", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ wrappedPrivateKey: bytesToBase64(wrappedPrivateKey), kdfParams: { salt: bytesToHex(salt), iterations: KDF_ITERATIONS }, recoveryAuthHash }),
  });
  if (!res.ok) throw await failed(res, "regenerate recovery failed");
  return recoveryCode;
}

export async function putRecoveryEnvelope(e: { wrappedDEK: string; ephemeralPublicKeyJwk: unknown }): Promise<{ status: string }> {
  const res = await fetch("/api/vault/recovery-envelope", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(e),
  });
  if (!res.ok) throw await failed(res, "put recovery envelope failed");
  return res.json();
}

export async function revokeRecoveryEnvelope(): Promise<{ status: string; revokedAt: string }> {
  const res = await fetch("/api/vault/recovery-envelope", { method: "DELETE" });
  if (!res.ok) throw await failed(res, "revoke recovery envelope failed");
  return res.json();
}

export interface AccessEventRow {
  id: string;
  action: string;
  actorAccountId: string;
  vaultId: string | null;
  consentRef: string | null;
  meta: unknown;
  createdAt: string;
}
export async function getAccessEvents(): Promise<{ events: AccessEventRow[] }> {
  const res = await fetch("/api/account/access-events", { cache: "no-store" });
  if (!res.ok) throw await failed(res, "access events failed");
  return res.json();
}
