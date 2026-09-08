import {
  MemoryAccountStore,
  MemoryCredentialStore,
  MemoryEnvelopeStore,
  MemoryProviderLinkStore,
  MemoryAuditStore,
} from "../adapters/memory";
import {
  runAccountStoreConformance,
  runCredentialStoreConformance,
  runEnvelopeStoreConformance,
  runProviderLinkStoreConformance,
  runAuditStoreConformance,
} from "../adapters/conformance";

// Runs the same contract suite the D1 adapter satisfies (in the health-dash-web adopter, via
// Miniflare) against these plain in-memory stores instead. Two structurally unrelated adapters
// passing identical assertions is the actual evidence "storage-agnostic" holds, not just an
// assertion made by interface shape (see ARCHITECTURE.md's "## Adapters" section).

runAccountStoreConformance("memory", () => new MemoryAccountStore());
runCredentialStoreConformance("memory", () => new MemoryCredentialStore());
runEnvelopeStoreConformance("memory", () => new MemoryEnvelopeStore());
runProviderLinkStoreConformance("memory", () => new MemoryProviderLinkStore());
runAuditStoreConformance("memory", () => new MemoryAuditStore());
