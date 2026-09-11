// Browser-side orchestration for password signup/login. All crypto primitives
// live in ./crypto (do not reimplement); this file only wires them to fetch calls against
// an adopter's own password-auth endpoints. The server never sees a password, a KEK, or a DEK.
import {
  generateAccountKeypair,
  deriveKekFromPassword,
  deriveAuthHash,
  wrapPrivateKey,
  unwrapPrivateKey,
  generateDEK,
  encryptVaultV2,
  wrapDEKForPublicKey,
  unwrapDEKWithPrivateKey,
  kekFromPrfSecret,
  importPrivateKeyPkcs8,
} from "./crypto";
import { startRegistration, startAuthentication, base64URLStringToBuffer } from "@simplewebauthn/browser";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { bytesToB64 as bytesToBase64, b64ToBytes as base64ToBytes } from "./base64";
import type { ProviderKind } from "./stores";
export { bytesToB64 as bytesToBase64, b64ToBytes as base64ToBytes } from "./base64";

export const KDF_ITERATIONS = 200_000;
export const rand = (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

// The org-recovery public key, fetched pre-session (signup has no session yet; a public key
// is public regardless of who asks for it).
/**
 * The error the server actually wrote, when it wrote one.
 *
 * Nearly every branch below threw `${what} failed: ${res.status}`, discarding a message the
 * endpoint had already composed for exactly this moment ("that recovery code has expired", "this
 * provider already has access", "no access to this vault") and showing an owner a bare number
 * instead. These are the paths a person is on during the worst day they will have with this app, and
 * a status code tells them nothing about whether to retry, wait, or ask someone.
 *
 * The status is kept in the fallback so a failure with no body is still diagnosable. Deliberately NOT
 * used on the salt lookups: those return a decoy for an unknown address, so any detail there would be
 * an answer about whether the account exists.
 */
export async function failed(res: Response, what: string): Promise<Error> {
  const body = (await res.json().catch(() => null)) as { error?: string } | null;
  return new Error(body?.error?.trim() || `${what} (${res.status})`);
}

export async function getOrgKey(): Promise<{ orgAccountId: string; orgPublicKeyJwk: JsonWebKey }> {
  const res = await fetch("/api/vault/org-key");
  if (!res.ok) throw await failed(res, "org key failed");
  return res.json();
}

// Everything below this point that authenticates a stranger — signup, both login paths, the Google
// bootstrap, and redeeming a recovery code — deliberately does NOT use `failed()`. A reason there is
// an answer about whether an address is registered, which is the enumeration oracle the decoy salt at
// /api/auth/salt exists to close — an adopter's own tests are where "the enumeration oracle stays
// closed" gets pinned. Once a session exists there is nobody left to enumerate to, and the server's
// message helps.
export async function signupPassword(
  email: string,
  displayName: string,
  password: string
): Promise<{ accountId: string; vaultId: string }> {
  const { publicKeyJwk, privateKey } = await generateAccountKeypair();

  const salt = rand(16);
  const kek = await deriveKekFromPassword(password, salt);
  const wrappedPrivateKey = await wrapPrivateKey(privateKey, kek);
  const authHash = await deriveAuthHash(password, salt);

  const dek = await generateDEK();
  const vaultBlob = await encryptVaultV2({ clients: {} }, dek);
  const ownerEnvelope = await wrapDEKForPublicKey(dek, publicKeyJwk);
  const { orgPublicKeyJwk } = await getOrgKey();
  const orgEnvelope = await wrapDEKForPublicKey(dek, orgPublicKeyJwk);

  // No recovery credential at signup; the user mints one on demand from the Account menu.
  const res = await fetch("/api/auth/password/signup", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email,
      displayName,
      publicKeyJwk,
      wrappedPrivateKey: bytesToBase64(wrappedPrivateKey),
      kdfParams: { salt: bytesToHex(salt), iterations: KDF_ITERATIONS },
      authHash,
      vaultBlob: bytesToBase64(vaultBlob),
      ownerEnvelope: {
        wrappedDEK: bytesToBase64(ownerEnvelope.wrappedDEK),
        ephemeralPublicKeyJwk: ownerEnvelope.ephemeralPublicKeyJwk,
      },
      orgEnvelope: {
        wrappedDEK: bytesToBase64(orgEnvelope.wrappedDEK),
        ephemeralPublicKeyJwk: orgEnvelope.ephemeralPublicKeyJwk,
      },
    }),
  });
  if (!res.ok) throw new Error(`signup failed: ${res.status}`);
  const { accountId, vaultId } = (await res.json()) as { accountId: string; vaultId: string };
  return { accountId, vaultId };
}

export async function loginPassword(
  email: string,
  password: string
): Promise<{
  accountId: string;
  vaultId: string | null;
  r2Key: string | null;
  privateKey: CryptoKey;
  dek: CryptoKey | null;
  rotationPending: boolean;
}> {
  // Salt is public, but the client needs it before it can derive authHash — look it up
  // by email ahead of the login POST.
  const saltRes = await fetch(`/api/auth/password/salt?email=${encodeURIComponent(email)}`);
  // NOT "unknown account" any more. The endpoint returns a decoy salt for an address it does
  // not know, precisely so the browser cannot report which addresses are registered; a non-200 here
  // now means a malformed request or a server fault, and saying "unknown account" would both be
  // wrong and re-open the oracle in the UI text.
  if (!saltRes.ok) throw new Error(`sign-in is unavailable right now (${saltRes.status})`);
  const { salt } = (await saltRes.json()) as { salt: string; iterations: number };

  const authHash = await deriveAuthHash(password, hexToBytes(salt));

  const res = await fetch("/api/auth/password/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, authHash }),
  });
  if (!res.ok) throw new Error(`login failed: ${res.status}`);
  const data = (await res.json()) as {
    accountId: string;
    vaultId: string | null;
    r2Key: string | null;
    wrappedPrivateKey: string;
    kdfParams: { salt: string; iterations: number };
    ownerEnvelope: { wrappedDEK: string; ephemeralPublicKeyJwk: JsonWebKey } | null;
  };

  const kek = await deriveKekFromPassword(password, hexToBytes(data.kdfParams.salt));
  const privateKey = await unwrapPrivateKey(base64ToBytes(data.wrappedPrivateKey), kek);
  const dek = data.ownerEnvelope
    ? await unwrapDEKWithPrivateKey(base64ToBytes(data.ownerEnvelope.wrappedDEK), data.ownerEnvelope.ephemeralPublicKeyJwk, privateKey)
    : null;

  return { accountId: data.accountId, vaultId: data.vaultId, r2Key: data.r2Key, privateKey, dek, rotationPending: (data as { rotationPending?: boolean }).rotationPending ?? false };
}

// Browser-side orchestration for passkey (WebAuthn + PRF) signup/login. Mirrors
// signupPassword/loginPassword above: all crypto stays in ./crypto, this file only wires it to
// startRegistration/startAuthentication and an adopter's own passkey-auth endpoints. The server
// never sees the PRF secret, a KEK, or a DEK.

// The server sends the PRF extension's `eval.first` as a base64url STRING (see webauthn.ts) —
// startRegistration/startAuthentication spread `extensions` straight into
// navigator.credentials.{create,get}() without decoding custom extensions, so we must convert
// it back into a BufferSource ourselves before calling them.
function preparePrfExtension<T extends { extensions?: unknown }>(optionsJSON: T): T {
  const ext = optionsJSON.extensions as { prf?: { eval?: { first?: string } } } | undefined;
  if (!ext?.prf?.eval?.first) return optionsJSON;
  return {
    ...optionsJSON,
    extensions: { ...ext, prf: { eval: { first: base64URLStringToBuffer(ext.prf.eval.first) } } },
  } as T;
}

function extractPrfSecret(clientExtensionResults: unknown): Uint8Array | null {
  const first = (clientExtensionResults as { prf?: { results?: { first?: ArrayBuffer } } } | undefined)?.prf?.results?.first;
  return first ? new Uint8Array(first) : null;
}

export async function signupPasskey(
  email: string,
  displayName: string
): Promise<{ accountId: string; vaultId: string }> {
  const optionsRes = await fetch("/api/auth/passkey/register/options", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, displayName }),
  });
  if (!optionsRes.ok) throw await failed(optionsRes, "register options failed");
  const optionsJSON = (await optionsRes.json()) as PublicKeyCredentialCreationOptionsJSON;
  const prfSaltB64 = (optionsJSON.extensions as { prf?: { eval?: { first?: string } } } | undefined)?.prf?.eval?.first;
  if (!prfSaltB64) throw new Error("registration options missing the PRF extension");

  const attestationResponse = await startRegistration({ optionsJSON: preparePrfExtension(optionsJSON) });

  let prfSecret = extractPrfSecret(attestationResponse.clientExtensionResults);
  if (!prfSecret) {
    // Some authenticators don't evaluate PRF during create() — fall back to a local get()
    // ceremony against the credential we just made, purely to read the PRF secret. This is not
    // sent to the server; the create() attestation above is what gets verified server-side.
    const fallbackOptions: PublicKeyCredentialRequestOptionsJSON = {
      challenge: bytesToBase64(rand(16)),
      allowCredentials: [{ id: attestationResponse.id, type: "public-key", transports: attestationResponse.response.transports }],
      userVerification: "preferred",
      extensions: { prf: { eval: { first: base64URLStringToBuffer(prfSaltB64) } } } as PublicKeyCredentialRequestOptionsJSON["extensions"],
    };
    const fallbackAssertion = await startAuthentication({ optionsJSON: fallbackOptions });
    prfSecret = extractPrfSecret(fallbackAssertion.clientExtensionResults);
    if (!prfSecret) throw new Error("authenticator does not support the PRF extension");
  }

  const kek = await kekFromPrfSecret(prfSecret);
  const { publicKeyJwk, privateKey } = await generateAccountKeypair();
  const wrappedPrivateKey = await wrapPrivateKey(privateKey, kek);

  const dek = await generateDEK();
  const vaultBlob = await encryptVaultV2({ clients: {} }, dek);
  const ownerEnvelope = await wrapDEKForPublicKey(dek, publicKeyJwk);
  const { orgPublicKeyJwk } = await getOrgKey();
  const orgEnvelope = await wrapDEKForPublicKey(dek, orgPublicKeyJwk);

  // No recovery credential at signup; minted on demand from the Account menu.
  const verifyRes = await fetch("/api/auth/passkey/register/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      attestationResponse,
      publicKeyJwk,
      wrappedPrivateKey: bytesToBase64(wrappedPrivateKey),
      vaultBlob: bytesToBase64(vaultBlob),
      ownerEnvelope: {
        wrappedDEK: bytesToBase64(ownerEnvelope.wrappedDEK),
        ephemeralPublicKeyJwk: ownerEnvelope.ephemeralPublicKeyJwk,
      },
      orgEnvelope: {
        wrappedDEK: bytesToBase64(orgEnvelope.wrappedDEK),
        ephemeralPublicKeyJwk: orgEnvelope.ephemeralPublicKeyJwk,
      },
      prfSaltHex: bytesToHex(new Uint8Array(base64URLStringToBuffer(prfSaltB64))),
    }),
  });
  if (!verifyRes.ok) throw await failed(verifyRes, "register verify failed");
  const { accountId, vaultId } = (await verifyRes.json()) as { accountId: string; vaultId: string };
  return { accountId, vaultId };
}

export async function loginPasskey(
  email: string
): Promise<{ accountId: string; vaultId: string | null; r2Key: string | null; privateKey: CryptoKey; dek: CryptoKey | null; rotationPending: boolean }> {
  const optionsRes = await fetch("/api/auth/passkey/login/options", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email }),
  });
  if (!optionsRes.ok) throw new Error(`login options failed: ${optionsRes.status}`);
  const optionsJSON = (await optionsRes.json()) as PublicKeyCredentialRequestOptionsJSON;

  const authenticationResponse = await startAuthentication({ optionsJSON: preparePrfExtension(optionsJSON) });
  const prfSecret = extractPrfSecret(authenticationResponse.clientExtensionResults);
  if (!prfSecret) throw new Error("authenticator did not return a PRF secret");

  const verifyRes = await fetch("/api/auth/passkey/login/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ authenticationResponse }),
  });
  if (!verifyRes.ok) throw new Error(`login verify failed: ${verifyRes.status}`);
  const data = (await verifyRes.json()) as {
    accountId: string;
    vaultId: string | null;
    r2Key: string | null;
    wrappedPrivateKey: string;
    prfSalt: string;
    ownerEnvelope: { wrappedDEK: string; ephemeralPublicKeyJwk: JsonWebKey } | null;
  };

  const kek = await kekFromPrfSecret(prfSecret);
  const privateKey = await unwrapPrivateKey(base64ToBytes(data.wrappedPrivateKey), kek);
  const dek = data.ownerEnvelope
    ? await unwrapDEKWithPrivateKey(base64ToBytes(data.ownerEnvelope.wrappedDEK), data.ownerEnvelope.ephemeralPublicKeyJwk, privateKey)
    : null;

  return { accountId: data.accountId, vaultId: data.vaultId, r2Key: data.r2Key, privateKey, dek, rotationPending: (data as { rotationPending?: boolean }).rotationPending ?? false };
}

// Google login bootstrap. After the OAuth callback redirects to /?google=1 the session is
// already set; this fetches the server-unwrapped private key + owner envelope and recovers the DEK
// client-side. Returns the same shape as loginPassword so it flows straight into an adopter's own
// account-entry step. Unlike password/passkey, the private key is handed over by the server
// (server-custody) rather than unwrapped from a client-held secret.
export async function bootstrapGoogleSession(): Promise<{
  accountId: string;
  vaultId: string | null;
  r2Key: string | null;
  privateKey: CryptoKey;
  dek: CryptoKey | null;
  rotationPending: boolean;
}> {
  const res = await fetch("/api/auth/google/session", { cache: "no-store" });
  if (!res.ok) throw new Error(`google session failed: ${res.status}`);
  const data = (await res.json()) as {
    accountId: string;
    vaultId: string | null;
    r2Key: string | null;
    rotationPending: boolean;
    privateKeyPkcs8: string;
    ownerEnvelope: { wrappedDEK: string; ephemeralPublicKeyJwk: JsonWebKey } | null;
  };
  const privateKey = await importPrivateKeyPkcs8(base64ToBytes(data.privateKeyPkcs8));
  const dek = data.ownerEnvelope
    ? await unwrapDEKWithPrivateKey(base64ToBytes(data.ownerEnvelope.wrappedDEK), data.ownerEnvelope.ephemeralPublicKeyJwk, privateKey)
    : null;
  return { accountId: data.accountId, vaultId: data.vaultId, r2Key: data.r2Key, privateKey, dek, rotationPending: data.rotationPending };
}

// Plain-refresh resume (password/passkey). Session-gated read of the vault location + owner DEK
// envelope; the client already holds the account private key (non-extractable, from IndexedDB) and
// unwraps the DEK locally. Returns null when there's no valid session (401) so the caller can fall
// back to the lock screen. Does NOT return the wrapped private key — the key never leaves the device.
export async function resumeSession(): Promise<{
  accountId: string;
  vaultId: string | null;
  r2Key: string | null;
  rotationPending: boolean;
  providerKind: ProviderKind | null;
  ownerEnvelope: { wrappedDEK: string; ephemeralPublicKeyJwk: JsonWebKey } | null;
} | null> {
  const res = await fetch("/api/auth/session/resume", { cache: "no-store" });
  if (res.status === 401) return null;
  if (!res.ok) throw await failed(res, "resume failed");
  return res.json();
}

// Finish adding Google to the signed-in account. The OAuth popup already set the signed
// link cookie (bound to this account + the verified sub); here we hand the server the in-memory
// private key so it can wrap it under the server KEK. The sub is trusted from the cookie, not us.
export async function addGoogleMethod(privateKey: CryptoKey, currentPassword?: string, email?: string): Promise<void> {
  const currentAuthHash = await currentAuthHashFor(email, currentPassword);
  const pkcs8 = new Uint8Array(await globalThis.crypto.subtle.exportKey("pkcs8", privateKey));
  const res = await fetch("/api/account/methods/google", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ privateKeyPkcs8: bytesToBase64(pkcs8), ...(currentAuthHash ? { currentAuthHash } : {}) }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `add google failed: ${res.status}`);
}

export async function getMyAccount(): Promise<{ id: string; email: string | null; emailConfirmed: boolean; displayName: string; providerKind: ProviderKind | null; unitSystem: "metric" | "imperial" | null }> {
  const res = await fetch("/api/account", { cache: "no-store" });
  if (!res.ok) throw await failed(res, "account fetch failed");
  return res.json();
}

// Account settings. Change email/display name; add/remove a login method (password/passkey).
// Adding a method re-wraps the account's in-memory private key under the new method's KEK — same
// zero-knowledge model as signup; the server never sees the key.

/**
 * The step-up proof, derived the same way the login path derives its authHash.
 *
 * Shared by all three add-a-method calls. Adding a passkey or a Google identity used to need only a
 * session cookie, which meant a captured cookie could mint a credential that outlived it; the server
 * now challenges those paths too, so all three send the same proof.
 *
 * Returns undefined when there is nothing to prove — an account with no password cannot be challenged,
 * and the server treats that case as allowed-and-notified rather than refusing it.
 */
export async function currentAuthHashFor(email?: string, currentPassword?: string): Promise<string | undefined> {
  if (!currentPassword || !email) return undefined;
  const saltRes = await fetch(`/api/auth/password/salt?email=${encodeURIComponent(email)}`);
  if (!saltRes.ok) throw new Error(`could not verify your current password (${saltRes.status})`);
  const { salt: currentSalt } = (await saltRes.json()) as { salt: string };
  return deriveAuthHash(currentPassword, hexToBytes(currentSalt));
}

export async function addPasskeyMethod(privateKey: CryptoKey, currentPassword?: string, email?: string): Promise<void> {
  const currentAuthHash = await currentAuthHashFor(email, currentPassword);
  const optionsRes = await fetch("/api/account/methods/passkey/options", { method: "POST" });
  if (!optionsRes.ok) throw await failed(optionsRes, "passkey options failed");
  const optionsJSON = (await optionsRes.json()) as PublicKeyCredentialCreationOptionsJSON;
  const prfSaltB64 = (optionsJSON.extensions as { prf?: { eval?: { first?: string } } } | undefined)?.prf?.eval?.first;
  if (!prfSaltB64) throw new Error("registration options missing the PRF extension");

  const attestationResponse = await startRegistration({ optionsJSON: preparePrfExtension(optionsJSON) });
  let prfSecret = extractPrfSecret(attestationResponse.clientExtensionResults);
  if (!prfSecret) {
    // Some authenticators don't evaluate PRF during create() — read it via a local get() (not sent).
    const fallbackAssertion = await startAuthentication({
      optionsJSON: {
        challenge: bytesToBase64(rand(16)),
        allowCredentials: [{ id: attestationResponse.id, type: "public-key", transports: attestationResponse.response.transports }],
        userVerification: "preferred",
        extensions: { prf: { eval: { first: base64URLStringToBuffer(prfSaltB64) } } } as PublicKeyCredentialRequestOptionsJSON["extensions"],
      },
    });
    prfSecret = extractPrfSecret(fallbackAssertion.clientExtensionResults);
    if (!prfSecret) throw new Error("authenticator does not support the PRF extension");
  }

  const kek = await kekFromPrfSecret(prfSecret);
  const wrappedPrivateKey = await wrapPrivateKey(privateKey, kek);
  const verifyRes = await fetch("/api/account/methods/passkey/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      attestationResponse,
      wrappedPrivateKey: bytesToBase64(wrappedPrivateKey),
      prfSaltHex: bytesToHex(new Uint8Array(base64URLStringToBuffer(prfSaltB64))),
      ...(currentAuthHash ? { currentAuthHash } : {}),
    }),
  });
  if (verifyRes.status === 401) {
    const { error } = (await verifyRes.json().catch(() => ({ error: "" }))) as { error?: string };
    throw new Error(error || "enter your current password to add a passkey");
  }
  if (!verifyRes.ok) throw await failed(verifyRes, "add passkey failed");
}
