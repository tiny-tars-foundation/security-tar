import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { r2Sink, rememberVaultEtag, knownVaultEtag, VaultConflictError, setVaultConflictHandler } from "../vault-sink";

// The client half of optimistic concurrency.
//
// The sink holds the version token because a real caller has multiple save call sites and only
// some go through a serialized queue. Since the precondition is required on the wire, a caller
// that forgot to pass one would 428 — so the token lives where the request is built, and every
// path is correct by construction.

const ID = "pablo";
const blob = () => new Uint8Array([0x48, 0x44, 0x31, 2]);

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  rememberVaultEtag(ID, null);
  setVaultConflictHandler(null);
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
  setVaultConflictHandler(null);
  rememberVaultEtag(ID, null);
});

const ok = (etag?: string) =>
  new Response(null, { status: 204, headers: etag ? { ETag: etag } : {} });

function headersOf(): Record<string, string> {
  return fetchMock.mock.calls[0][1].headers as Record<string, string>;
}

describe("the vault sink states which version it is replacing", () => {
  it("sends If-None-Match:* when it has never seen this vault — create, never clobber", async () => {
    fetchMock.mockResolvedValue(ok("e1"));
    await r2Sink.put(ID, blob());
    expect(headersOf()["If-None-Match"]).toBe("*");
    expect(headersOf()["If-Match"]).toBeUndefined();
  });

  it("sends If-Match once a version is known", async () => {
    rememberVaultEtag(ID, "e1");
    fetchMock.mockResolvedValue(ok("e2"));
    await r2Sink.put(ID, blob());
    expect(headersOf()["If-Match"]).toBe("e1");
    expect(headersOf()["If-None-Match"]).toBeUndefined();
  });

  // Without this the SECOND save of a session always fails: the first would consume the create
  // case and the next would still claim the vault does not exist.
  it("adopts the version returned by a successful save", async () => {
    fetchMock.mockResolvedValue(ok("e2"));
    await r2Sink.put(ID, blob());
    expect(knownVaultEtag(ID)).toBe("e2");
  });

  it("a 412 throws a TYPED conflict carrying the server's current version", async () => {
    rememberVaultEtag(ID, "stale");
    fetchMock.mockResolvedValue(new Response("{}", { status: 412, headers: { ETag: "current" } }));
    await expect(r2Sink.put(ID, blob())).rejects.toBeInstanceOf(VaultConflictError);
  });

  // Typed, not string-matched: "someone else edited this record" and "the network is down"
  // deserve completely different responses, and only one of them must block the caller's UI.
  it("an ordinary failure is NOT a conflict", async () => {
    rememberVaultEtag(ID, "e1");
    fetchMock.mockResolvedValue(new Response("boom", { status: 500 }));
    await expect(r2Sink.put(ID, blob())).rejects.not.toBeInstanceOf(VaultConflictError);
  });

  it("a conflict does not adopt the server's version — the caller decides", async () => {
    rememberVaultEtag(ID, "stale");
    fetchMock.mockResolvedValue(new Response("{}", { status: 412, headers: { ETag: "current" } }));
    await r2Sink.put(ID, blob()).catch(() => {});
    expect(knownVaultEtag(ID)).toBe("stale");
  });

  // The hook is what lets direct (unqueued) save paths report a conflict at all.
  it("reports every conflict through the single handler, and still throws", async () => {
    const seen: VaultConflictError[] = [];
    setVaultConflictHandler((e) => seen.push(e));
    rememberVaultEtag(ID, "stale");
    fetchMock.mockResolvedValue(new Response("{}", { status: 412, headers: { ETag: "current" } }));
    await expect(r2Sink.put(ID, blob())).rejects.toBeInstanceOf(VaultConflictError);
    expect(seen).toHaveLength(1);
    expect(seen[0].serverEtag).toBe("current");
  });
});

// The app must never conflict with ITSELF.
//
// Some callers await saveVaultV2 directly rather than through a queue, so two saves to the same
// vault can be in flight together. Each reads the version token when it builds its request, so an
// overlapping pair would have the second sending a token the first already superseded — a
// conflict reported against a tab racing only itself.
describe("writes to one vault never overlap", () => {
  it("the second PUT sends the version the FIRST one produced", async () => {
    const sent: (string | undefined)[] = [];
    let releaseFirst: () => void = () => {};
    const firstInFlight = new Promise<void>((r) => (releaseFirst = r));

    fetchMock.mockImplementation(async (_url: string, init: RequestInit) => {
      const h = init.headers as Record<string, string>;
      sent.push(h["If-Match"] ?? h["If-None-Match"]);
      if (sent.length === 1) await firstInFlight;
      return ok(`e${sent.length}`);
    });

    rememberVaultEtag(ID, "e0");
    const a = r2Sink.put(ID, blob());
    const b = r2Sink.put(ID, blob()); // queued while A is still in flight
    releaseFirst();
    await Promise.all([a, b]);

    // Without serialization both would have sent "e0" and the second would 412 against itself.
    expect(sent).toEqual(["e0", "e1"]);
  });

  it("a failed write does not poison the writes queued behind it", async () => {
    rememberVaultEtag(ID, "e0");
    fetchMock
      .mockResolvedValueOnce(new Response("boom", { status: 500 }))
      .mockResolvedValueOnce(ok("e1"));

    const failed = r2Sink.put(ID, blob());
    const after = r2Sink.put(ID, blob());
    await expect(failed).rejects.toThrow(/save failed/);
    await expect(after).resolves.toBeUndefined();
  });
});
