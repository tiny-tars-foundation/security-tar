// W49 — persist the account private key across a browser refresh so a valid hd_session doesn't force
// re-auth. The key is stored as a NON-EXTRACTABLE CryptoKey (structured-cloned into IndexedDB): it can
// still unwrap the vault DEK (ECDH deriveKey) on the next load, but its raw bytes can't be read back
// out, so an XSS payload can't exfiltrate it (it could still USE it while the page is open — inherent
// to any "stay signed in"). Password/passkey only; Google re-bootstraps from server-custody material.

const DB_NAME = "hd-session";
const STORE = "keys";
const KEY_ID = "account-private-key";
const EC_PARAMS = { name: "ECDH", namedCurve: "P-256" } as const;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// Store a non-extractable copy of the (currently extractable, in-memory) account private key. Silent
// no-op if IndexedDB is unavailable (private-browsing / disabled) — persistence is best-effort; the
// session still works for the current page, the user just re-auths on the next refresh.
export async function putAccountKey(extractableKey: CryptoKey): Promise<void> {
  const subtle = (globalThis.crypto as Crypto).subtle;
  const pkcs8 = await subtle.exportKey("pkcs8", extractableKey);
  const nonExtractable = await subtle.importKey("pkcs8", pkcs8, EC_PARAMS, false, ["deriveKey", "deriveBits"]);
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(nonExtractable, KEY_ID);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

export async function getAccountKey(): Promise<CryptoKey | null> {
  const db = await openDb();
  try {
    return await new Promise<CryptoKey | null>((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get(KEY_ID);
      req.onsuccess = () => resolve((req.result as CryptoKey | undefined) ?? null);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

export async function clearAccountKey(): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete(KEY_ID);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}
